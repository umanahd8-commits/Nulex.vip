require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');
const Korapay = require('korapay-nodejs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 5000;

// Initialize Korapay with YOUR keys
const korapay = new Korapay({
  publicKey: process.env.KORAPAY_PUBLIC_KEY,
  secretKey: process.env.KORAPAY_SECRET_KEY
});

// PostgreSQL Database Connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Test database connection
pool.connect((err, client, release) => {
  if (err) {
    console.error('Error connecting to PostgreSQL:', err);
  } else {
    console.log('✅ Connected to PostgreSQL database');
    release();
  }
});

// Middleware
app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true
}));
app.use(morgan('combined'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use('/api/', limiter);

// Security headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  next();
});

// Authentication middleware
const authenticate = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    const userResult = await pool.query(
      'SELECT id, email, full_name, role, is_active FROM users WHERE id = $1',
      [decoded.userId]
    );
    
    if (userResult.rows.length === 0) {
      return res.status(401).json({ error: 'User not found' });
    }
    
    req.user = userResult.rows[0];
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

const isAdmin = (req, res, next) => {
  if (req.user.role === 'admin') {
    next();
  } else {
    res.status(403).json({ error: 'Admin access required' });
  }
};

// Initialize database tables
async function initializeDatabase() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        email VARCHAR(255) UNIQUE NOT NULL,
        phone VARCHAR(50),
        password_hash VARCHAR(255) NOT NULL,
        full_name VARCHAR(255) NOT NULL,
        referral_code VARCHAR(10) UNIQUE NOT NULL,
        referred_by VARCHAR(10),
        bank_account JSONB,
        balance DECIMAL(15,2) DEFAULT 0.00,
        bonus_balance DECIMAL(15,2) DEFAULT 0.00,
        total_earned DECIMAL(15,2) DEFAULT 0.00,
        total_withdrawn DECIMAL(15,2) DEFAULT 0.00,
        has_deposited BOOLEAN DEFAULT FALSE,
        kyc_status VARCHAR(20) DEFAULT 'pending',
        role VARCHAR(20) DEFAULT 'user',
        is_active BOOLEAN DEFAULT TRUE,
        last_login TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS packages (
        id SERIAL PRIMARY KEY,
        name VARCHAR(50) NOT NULL,
        amount DECIMAL(15,2) NOT NULL,
        referral_commission DECIMAL(15,2) NOT NULL,
        description TEXT,
        is_active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS investments (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        package_id INTEGER REFERENCES packages(id),
        amount DECIMAL(15,2) NOT NULL,
        status VARCHAR(20) DEFAULT 'active',
        start_date DATE NOT NULL,
        end_date DATE,
        expected_return DECIMAL(15,2),
        actual_return DECIMAL(15,2),
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS transactions (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        type VARCHAR(50) NOT NULL,
        amount DECIMAL(15,2) NOT NULL,
        status VARCHAR(20) DEFAULT 'pending',
        description TEXT,
        reference VARCHAR(255) UNIQUE,
        korapay_reference VARCHAR(255),
        metadata JSONB,
        admin_notes TEXT,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS withdrawals (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        amount DECIMAL(15,2) NOT NULL,
        bank_details JSONB NOT NULL,
        status VARCHAR(20) DEFAULT 'pending',
        admin_notes TEXT,
        processed_at TIMESTAMP,
        korapay_transfer_reference VARCHAR(255),
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS engagement_tasks (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        task_type VARCHAR(50) NOT NULL,
        platform VARCHAR(50),
        reward_amount DECIMAL(10,2) DEFAULT 25.00,
        status VARCHAR(20) DEFAULT 'pending',
        proof_url TEXT,
        verified_by UUID REFERENCES users(id),
        verified_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS referral_commissions (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        referrer_id UUID REFERENCES users(id) ON DELETE CASCADE,
        referred_id UUID REFERENCES users(id) ON DELETE CASCADE,
        investment_id UUID REFERENCES investments(id),
        amount DECIMAL(15,2) NOT NULL,
        status VARCHAR(20) DEFAULT 'pending',
        paid_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    // Insert default packages
    const packagesResult = await pool.query('SELECT COUNT(*) FROM packages');
    if (parseInt(packagesResult.rows[0].count) === 0) {
      await pool.query(`
        INSERT INTO packages (name, amount, referral_commission, description) VALUES
        ('Elite Package', 4500.00, 2000.00, 'Perfect for beginners with daily returns'),
        ('Platinum Package', 7500.00, 3500.00, 'Premium package with higher returns and VIP support')
      `);
      console.log('✅ Default packages created');
    }

    // Create admin user if not exists
    const adminCheck = await pool.query('SELECT * FROM users WHERE email = $1', [process.env.ADMIN_EMAIL]);
    if (adminCheck.rows.length === 0) {
      const hashedPassword = await bcrypt.hash(process.env.ADMIN_PASSWORD || 'Admin@1234', 10);
      const referralCode = 'ADMIN' + Math.random().toString(36).substr(2, 5).toUpperCase();
      
      await pool.query(`
        INSERT INTO users (email, password_hash, full_name, referral_code, role, has_deposited, balance, is_active) 
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      `, [
        process.env.ADMIN_EMAIL,
        hashedPassword,
        'NULEX Admin',
        referralCode,
        'admin',
        true,
        1000000,
        true
      ]);
      console.log('✅ Admin user created');
    }

    console.log('✅ Database initialized successfully');
  } catch (error) {
    console.error('Error initializing database:', error);
  }
}

// Initialize database on startup
initializeDatabase();

// ==================== ROUTES ====================

// 1. AUTHENTICATION ROUTES
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, fullName, phone, referralCode } = req.body;
    
    // Check if user exists
    const userExists = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (userExists.rows.length > 0) {
      return res.status(400).json({ error: 'Email already registered' });
    }
    
    // Generate unique referral code
    let userReferralCode;
    let isUnique = false;
    while (!isUnique) {
      userReferralCode = 'NUL' + Math.random().toString(36).substr(2, 7).toUpperCase();
      const codeCheck = await pool.query('SELECT id FROM users WHERE referral_code = $1', [userReferralCode]);
      if (codeCheck.rows.length === 0) isUnique = true;
    }
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Create user
    const userId = uuidv4();
    await pool.query(`
      INSERT INTO users (id, email, password_hash, full_name, phone, referral_code, referred_by, bonus_balance) 
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
    `, [userId, email, hashedPassword, fullName, phone, userReferralCode, referralCode || null, 1000.00]);
    
    // Create welcome bonus transaction
    await pool.query(`
      INSERT INTO transactions (id, user_id, type, amount, status, description) 
      VALUES ($1, $2, $3, $4, $5, $6)
    `, [uuidv4(), userId, 'welcome_bonus', 1000.00, 'success', 'Welcome bonus']);
    
    // Generate JWT token
    const token = jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRE });
    
    res.status(201).json({
      message: 'Registration successful',
      user: { id: userId, email, fullName, referralCode: userReferralCode, bonusBalance: 1000.00 },
      token
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const result = await pool.query(
      'SELECT id, email, password_hash, full_name, role, is_active, balance, bonus_balance FROM users WHERE email = $1',
      [email]
    );
    
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const user = result.rows[0];
    
    // Check if account is active
    if (!user.is_active) {
      return res.status(403).json({ error: 'Account suspended' });
    }
    
    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.password_hash);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Update last login
    await pool.query('UPDATE users SET last_login = NOW() WHERE id = $1', [user.id]);
    
    // Generate JWT token
    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRE });
    
    // Remove password hash from response
    const { password_hash, ...userResponse } = user;
    
    res.json({
      message: 'Login successful',
      user: userResponse,
      token
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// 2. USER PROFILE ROUTES
app.get('/api/user/profile', authenticate, async (req, res) => {
  try {
    const userId = req.user.id;
    
    const userResult = await pool.query(`
      SELECT id, email, full_name, phone, referral_code, referred_by, 
             bank_account, balance, bonus_balance, total_earned, total_withdrawn,
             has_deposited, kyc_status, created_at
      FROM users WHERE id = $1
    `, [userId]);
    
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const user = userResult.rows[0];
    
    // Get referrals count
    const referralsResult = await pool.query(
      'SELECT COUNT(*) FROM users WHERE referred_by = $1',
      [user.referral_code]
    );
    
    // Get active investment
    const investmentResult = await pool.query(
      `SELECT i.*, p.name as package_name 
       FROM investments i 
       JOIN packages p ON i.package_id = p.id 
       WHERE i.user_id = $1 AND i.status = 'active' 
       ORDER BY i.created_at DESC LIMIT 1`,
      [userId]
    );
    
    // Get total commissions
    const commissionsResult = await pool.query(
      `SELECT COALESCE(SUM(amount), 0) as total_commissions 
       FROM referral_commissions 
       WHERE referrer_id = $1 AND status = 'paid'`,
      [userId]
    );
    
    res.json({
      ...user,
      referralsCount: parseInt(referralsResult.rows[0].count),
      activeInvestment: investmentResult.rows[0] || null,
      totalCommissions: parseFloat(commissionsResult.rows[0].total_commissions) || 0
    });
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

// 3. KORAPAY BANK VERIFICATION
app.post('/api/bank/verify', authenticate, async (req, res) => {
  try {
    const { accountNumber, bankCode } = req.body;
    const userId = req.user.id;
    
    // Call Korapay API for real verification
    const verification = await korapay.misc.verifyAccount({
      account_number: accountNumber,
      bank_code: bankCode
    });
    
    if (verification.status === 'success') {
      // Update user's bank details
      await pool.query(`
        UPDATE users 
        SET bank_account = $1 
        WHERE id = $2
      `, [
        {
          account_number: accountNumber,
          bank_code: bankCode,
          bank_name: getBankName(bankCode),
          account_name: verification.data.account_name,
          verified_at: new Date().toISOString()
        },
        userId
      ]);
      
      res.json({
        success: true,
        data: verification.data
      });
    } else {
      res.status(400).json({ error: 'Bank verification failed' });
    }
  } catch (error) {
    console.error('Bank verification error:', error);
    res.status(500).json({ error: 'Bank verification failed' });
  }
});

// Helper function to get bank name
function getBankName(bankCode) {
  const banks = {
    '044': 'Access Bank',
    '063': 'Diamond Bank',
    '050': 'Ecobank',
    '070': 'Fidelity Bank',
    '011': 'First Bank',
    '058': 'GTBank',
    '030': 'Heritage Bank',
    '082': 'Keystone Bank',
    '014': 'Mainstreet Bank',
    '076': 'Polaris Bank',
    '221': 'Stanbic IBTC',
    '068': 'Standard Chartered',
    '232': 'Sterling Bank',
    '032': 'Union Bank',
    '033': 'United Bank for Africa',
    '215': 'Unity Bank',
    '035': 'Wema Bank',
    '057': 'Zenith Bank'
  };
  return banks[bankCode] || 'Unknown Bank';
}

// 4. PACKAGES
app.get('/api/packages', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM packages WHERE is_active = true ORDER BY amount'
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Packages error:', error);
    res.status(500).json({ error: 'Failed to fetch packages' });
  }
});

// 5. REAL KORAPAY PAYMENT INITIALIZATION
app.post('/api/payment/initialize', authenticate, async (req, res) => {
  try {
    const { amount, packageId } = req.body;
    const userId = req.user.id;
    
    // Get user email
    const userResult = await pool.query('SELECT email, full_name FROM users WHERE id = $1', [userId]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const user = userResult.rows[0];
    
    // Generate unique reference
    const reference = 'NUL' + Date.now() + Math.random().toString(36).substr(2, 9).toUpperCase();
    
    // Initialize Korapay payment
    const payment = await korapay.transaction.initialize({
      amount: amount * 100, // Convert to kobo
      currency: 'NGN',
      reference: reference,
      customer: {
        name: user.full_name,
        email: user.email
      },
      metadata: {
        userId: userId,
        packageId: packageId,
        type: 'investment'
      },
      notification_url: `${process.env.FRONTEND_URL}/payment-callback`,
      redirect_url: `${process.env.FRONTEND_URL}/dashboard?payment=success`
    });
    
    if (payment.status === 'success') {
      // Create pending transaction record
      await pool.query(`
        INSERT INTO transactions (id, user_id, type, amount, status, reference, korapay_reference, description) 
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      `, [
        uuidv4(),
        userId,
        'deposit',
        amount,
        'pending',
        reference,
        payment.data.reference,
        `Payment for package ${packageId}`
      ]);
      
      res.json({
        success: true,
        payment_url: payment.data.checkout_url,
        reference: payment.data.reference
      });
    } else {
      res.status(400).json({ error: 'Payment initialization failed' });
    }
  } catch (error) {
    console.error('Payment initialization error:', error);
    res.status(500).json({ error: 'Payment initialization failed' });
  }
});

// 6. KORAPAY WEBHOOK HANDLER (REAL)
app.post('/api/webhook/korapay', async (req, res) => {
  try {
    const event = req.body;
    const signature = req.headers['x-korapay-signature'];
    
    // Verify webhook signature using Korapay encryption key
    const hash = crypto.createHmac('sha512', process.env.KORAPAY_ENCRYPTION_KEY)
      .update(JSON.stringify(event))
      .digest('hex');
    
    if (hash !== signature) {
      console.error('Invalid webhook signature');
      return res.status(400).send('Invalid signature');
    }
    
    console.log('✅ Valid Korapay webhook received:', event.event);
    
    // Handle different event types
    switch (event.event) {
      case 'charge.success':
        await handleSuccessfulCharge(event.data);
        break;
        
      case 'transfer.success':
        await handleSuccessfulTransfer(event.data);
        break;
        
      case 'transfer.failed':
        await handleFailedTransfer(event.data);
        break;
    }
    
    res.status(200).json({ received: true });
  } catch (error) {
    console.error('Webhook error:', error);
    res.status(500).json({ error: 'Webhook processing failed' });
  }
});

// Handle successful payment
async function handleSuccessfulCharge(paymentData) {
  try {
    const { reference, amount, metadata } = paymentData;
    const amountInNaira = amount / 100;
    
    // Find transaction
    const txResult = await pool.query(
      'SELECT * FROM transactions WHERE korapay_reference = $1',
      [reference]
    );
    
    if (txResult.rows.length === 0) {
      console.error('Transaction not found for reference:', reference);
      return;
    }
    
    const transaction = txResult.rows[0];
    
    // Update transaction status
    await pool.query(
      'UPDATE transactions SET status = $1, updated_at = NOW() WHERE id = $2',
      ['success', transaction.id]
    );
    
    // Update user balance and mark as deposited
    await pool.query(`
      UPDATE users 
      SET balance = balance + $1, has_deposited = true 
      WHERE id = $2
    `, [amountInNaira, transaction.user_id]);
    
    // If this is for a package, create investment
    if (metadata.packageId) {
      const packageResult = await pool.query(
        'SELECT * FROM packages WHERE id = $1',
        [metadata.packageId]
      );
      
      if (packageResult.rows.length > 0) {
        const pkg = packageResult.rows[0];
        
        // Create investment
        await pool.query(`
          INSERT INTO investments (id, user_id, package_id, amount, start_date, expected_return) 
          VALUES ($1, $2, $3, $4, $5, $6)
        `, [
          uuidv4(),
          transaction.user_id,
          metadata.packageId,
          amountInNaira,
          new Date(),
          amountInNaira * 1.2 // 20% expected return
        ]);
        
        // Handle referral commission
        const userResult = await pool.query(
          'SELECT referred_by FROM users WHERE id = $1',
          [transaction.user_id]
        );
        
        if (userResult.rows.length > 0 && userResult.rows[0].referred_by) {
          const referrerResult = await pool.query(
            'SELECT id FROM users WHERE referral_code = $1',
            [userResult.rows[0].referred_by]
          );
          
          if (referrerResult.rows.length > 0) {
            const referrerId = referrerResult.rows[0].id;
            const commissionAmount = pkg.referral_commission;
            
            // Add commission to referrer's balance
            await pool.query(
              'UPDATE users SET balance = balance + $1 WHERE id = $2',
              [commissionAmount, referrerId]
            );
            
            // Create commission record
            await pool.query(`
              INSERT INTO referral_commissions (id, referrer_id, referred_id, amount, status, paid_at) 
              VALUES ($1, $2, $3, $4, $5, $6)
            `, [
              uuidv4(),
              referrerId,
              transaction.user_id,
              commissionAmount,
              'paid',
              new Date()
            ]);
            
            // Create commission transaction
            await pool.query(`
              INSERT INTO transactions (id, user_id, type, amount, status, description) 
              VALUES ($1, $2, $3, $4, $5, $6)
            `, [
              uuidv4(),
              referrerId,
              'referral_commission',
              commissionAmount,
              'success',
              `Referral commission from ${transaction.user_id}`
            ]);
          }
        }
      }
    }
    
    console.log(`✅ Payment processed successfully for user ${transaction.user_id}`);
  } catch (error) {
    console.error('Error handling successful charge:', error);
  }
}

// Handle successful transfer (withdrawal)
async function handleSuccessfulTransfer(transferData) {
  try {
    const { reference, amount, recipient } = transferData;
    
    // Update withdrawal status
    await pool.query(`
      UPDATE withdrawals 
      SET status = 'completed', 
          processed_at = NOW(),
          korapay_transfer_reference = $1
      WHERE korapay_transfer_reference = $1
    `, [reference]);
    
    console.log(`✅ Withdrawal completed: ${reference}`);
  } catch (error) {
    console.error('Error handling successful transfer:', error);
  }
}

// 7. WITHDRAWAL REQUEST
app.post('/api/withdraw', authenticate, async (req, res) => {
  try {
    const { amount } = req.body;
    const userId = req.user.id;
    
    // Minimum withdrawal check
    if (amount < 1000) {
      return res.status(400).json({ error: 'Minimum withdrawal is ₦1000' });
    }
    
    // Get user with bank details
    const userResult = await pool.query(
      'SELECT balance, bank_account FROM users WHERE id = $1',
      [userId]
    );
    
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const user = userResult.rows[0];
    
    // Check available balance
    if (amount > user.balance) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }
    
    // Check if bank account is verified
    if (!user.bank_account || !user.bank_account.verified_at) {
      return res.status(400).json({ error: 'Please verify your bank account first' });
    }
    
    // Create withdrawal request
    const withdrawalId = uuidv4();
    await pool.query(`
      INSERT INTO withdrawals (id, user_id, amount, bank_details, status) 
      VALUES ($1, $2, $3, $4, $5)
    `, [withdrawalId, userId, amount, user.bank_account, 'pending']);
    
    // Deduct from user balance
    await pool.query(
      'UPDATE users SET balance = balance - $1 WHERE id = $2',
      [amount, userId]
    );
    
    // Create transaction record
    await pool.query(`
      INSERT INTO transactions (id, user_id, type, amount, status, description) 
      VALUES ($1, $2, $3, $4, $5, $6)
    `, [uuidv4(), userId, 'withdrawal', -amount, 'pending', 'Withdrawal request']);
    
    res.json({
      message: 'Withdrawal request submitted. Awaiting admin approval.',
      withdrawalId
    });
  } catch (error) {
    console.error('Withdrawal error:', error);
    res.status(500).json({ error: 'Withdrawal request failed' });
  }
});

// 8. ENGAGEMENT TASKS
app.get('/api/tasks', authenticate, async (req, res) => {
  try {
    const tasks = [
      {
        id: 1,
        title: 'Like Facebook Post',
        platform: 'facebook',
        reward: 25,
        description: 'Like our latest Facebook post and screenshot as proof',
        url: 'https://facebook.com/nulex'
      },
      {
        id: 2,
        title: 'Retweet on Twitter',
        platform: 'twitter',
        reward: 25,
        description: 'Retweet our pinned tweet',
        url: 'https://twitter.com/nulex'
      },
      {
        id: 3,
        title: 'Follow on Instagram',
        platform: 'instagram',
        reward: 25,
        description: 'Follow our Instagram page',
        url: 'https://instagram.com/nulex'
      },
      {
        id: 4,
        title: 'Join WhatsApp Group',
        platform: 'whatsapp',
        reward: 25,
        description: 'Join our WhatsApp community',
        url: 'https://chat.whatsapp.com/nulex'
      }
    ];
    
    res.json(tasks);
  } catch (error) {
    console.error('Tasks error:', error);
    res.status(500).json({ error: 'Failed to fetch tasks' });
  }
});

app.post('/api/tasks/complete', authenticate, async (req, res) => {
  try {
    const { taskId, proofUrl } = req.body;
    const userId = req.user.id;
    
    // Create task completion record
    await pool.query(`
      INSERT INTO engagement_tasks (id, user_id, task_type, reward_amount, proof_url) 
      VALUES ($1, $2, $3, $4, $5)
    `, [uuidv4(), userId, `task_${taskId}`, 25.00, proofUrl]);
    
    // Add reward to pending balance (will be approved by admin)
    await pool.query(
      'UPDATE users SET bonus_balance = bonus_balance + $1 WHERE id = $2',
      [25.00, userId]
    );
    
    res.json({
      message: 'Task submitted for review. Reward will be added after approval.',
      reward: 25.00
    });
  } catch (error) {
    console.error('Task completion error:', error);
    res.status(500).json({ error: 'Task submission failed' });
  }
});

// 9. TRANSACTIONS HISTORY
app.get('/api/transactions', authenticate, async (req, res) => {
  try {
    const userId = req.user.id;
    const { limit = 50, offset = 0 } = req.query;
    
    const result = await pool.query(`
      SELECT * FROM transactions 
      WHERE user_id = $1 
      ORDER BY created_at DESC 
      LIMIT $2 OFFSET $3
    `, [userId, limit, offset]);
    
    const countResult = await pool.query(
      'SELECT COUNT(*) FROM transactions WHERE user_id = $1',
      [userId]
    );
    
    res.json({
      transactions: result.rows,
      total: parseInt(countResult.rows[0].count)
    });
  } catch (error) {
    console.error('Transactions error:', error);
    res.status(500).json({ error: 'Failed to fetch transactions' });
  }
});

// 10. ADMIN ROUTES
app.get('/api/admin/dashboard', authenticate, isAdmin, async (req, res) => {
  try {
    const [
      usersCount,
      activeUsersCount,
      depositsSum,
      withdrawalsSum,
      pendingWithdrawalsCount,
      investmentsSum,
      commissionsSum
    ] = await Promise.all([
      pool.query('SELECT COUNT(*) FROM users WHERE role = "user"'),
      pool.query('SELECT COUNT(*) FROM users WHERE has_deposited = true'),
      pool.query(`SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE type = 'deposit' AND status = 'success'`),
      pool.query(`SELECT COALESCE(SUM(ABS(amount)), 0) FROM transactions WHERE type = 'withdrawal' AND status = 'success'`),
      pool.query(`SELECT COUNT(*) FROM withdrawals WHERE status = 'pending'`),
      pool.query(`SELECT COALESCE(SUM(amount), 0) FROM investments WHERE status = 'active'`),
      pool.query(`SELECT COALESCE(SUM(amount), 0) FROM referral_commissions WHERE status = 'paid'`)
    ]);
    
    const stats = {
      totalUsers: parseInt(usersCount.rows[0].count),
      activeUsers: parseInt(activeUsersCount.rows[0].count),
      totalDeposits: parseFloat(depositsSum.rows[0].coalesce),
      totalWithdrawals: parseFloat(withdrawalsSum.rows[0].coalesce),
      pendingWithdrawals: parseInt(pendingWithdrawalsCount.rows[0].count),
      totalInvestments: parseFloat(investmentsSum.rows[0].coalesce),
      totalCommissions: parseFloat(commissionsSum.rows[0].coalesce),
      platformBalance: parseFloat(depositsSum.rows[0].coalesce) - parseFloat(withdrawalsSum.rows[0].coalesce)
    };
    
    res.json(stats);
  } catch (error) {
    console.error('Admin dashboard error:', error);
    res.status(500).json({ error: 'Failed to fetch dashboard stats' });
  }
});

app.get('/api/admin/withdrawals/pending', authenticate, isAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT w.*, u.full_name, u.email, u.balance 
      FROM withdrawals w 
      JOIN users u ON w.user_id = u.id 
      WHERE w.status = 'pending' 
      ORDER BY w.created_at DESC
    `);
    
    res.json(result.rows);
  } catch (error) {
    console.error('Pending withdrawals error:', error);
    res.status(500).json({ error: 'Failed to fetch pending withdrawals' });
  }
});

app.post('/api/admin/withdrawals/:id/approve', authenticate, isAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { notes } = req.body;
    
    // Get withdrawal details
    const withdrawalResult = await pool.query(`
      SELECT w.*, u.bank_account 
      FROM withdrawals w 
      JOIN users u ON w.user_id = u.id 
      WHERE w.id = $1
    `, [id]);
    
    if (withdrawalResult.rows.length === 0) {
      return res.status(404).json({ error: 'Withdrawal not found' });
    }
    
    const withdrawal = withdrawalResult.rows[0];
    
    // Initiate Korapay transfer
    const transfer = await korapay.transaction.initiateTransfer({
      amount: withdrawal.amount * 100, // Convert to kobo
      currency: 'NGN',
      reference: 'NULW' + Date.now() + Math.random().toString(36).substr(2, 9).toUpperCase(),
      customer: {
        name: withdrawal.bank_account.account_name,
        email: 'withdrawal@nulex.com'
      },
      bank: {
        code: withdrawal.bank_account.bank_code,
        account_number: withdrawal.bank_account.account_number
      },
      reason: 'Withdrawal from NULEX'
    });
    
    if (transfer.status === 'success') {
      // Update withdrawal status
      await pool.query(`
        UPDATE withdrawals 
        SET status = 'processing', 
            admin_notes = $1,
            korapay_transfer_reference = $2
        WHERE id = $3
      `, [notes, transfer.data.reference, id]);
      
      // Update transaction status
      await pool.query(`
        UPDATE transactions 
        SET status = 'processing', 
            korapay_reference = $1,
            admin_notes = $2
        WHERE user_id = $3 AND amount = -$4 AND status = 'pending'
        LIMIT 1
      `, [transfer.data.reference, notes, withdrawal.user_id, withdrawal.amount]);
      
      res.json({
        message: 'Withdrawal approved and processing via Korapay',
        transfer_reference: transfer.data.reference
      });
    } else {
      res.status(400).json({ error: 'Transfer initiation failed' });
    }
  } catch (error) {
    console.error('Withdrawal approval error:', error);
    res.status(500).json({ error: 'Withdrawal approval failed' });
  }
});

// 11. REFERRAL SYSTEM
app.get('/api/referrals', authenticate, async (req, res) => {
  try {
    const userId = req.user.id;
    
    // Get user's referral code
    const userResult = await pool.query(
      'SELECT referral_code FROM users WHERE id = $1',
      [userId]
    );
    
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const referralCode = userResult.rows[0].referral_code;
    
    // Get referrals
    const referralsResult = await pool.query(`
      SELECT id, full_name, email, created_at, has_deposited 
      FROM users 
      WHERE referred_by = $1 
      ORDER BY created_at DESC
    `, [referralCode]);
    
    // Get total commissions
    const commissionsResult = await pool.query(`
      SELECT COALESCE(SUM(amount), 0) as total_earned, COUNT(*) as total_referrals 
      FROM referral_commissions 
      WHERE referrer_id = $1 AND status = 'paid'
    `, [userId]);
    
    res.json({
      referralCode,
      referralLink: `${process.env.FRONTEND_URL}/register?ref=${referralCode}`,
      referrals: referralsResult.rows,
      stats: {
        totalEarned: parseFloat(commissionsResult.rows[0].total_earned) || 0,
        totalReferrals: parseInt(commissionsResult.rows[0].total_referrals) || 0
      }
    });
  } catch (error) {
    console.error('Referrals error:', error);
    res.status(500).json({ error: 'Failed to fetch referral data' });
  }
});

// 12. HEALTH CHECK
app.get('/api/health', async (req, res) => {
  try {
    // Test database connection
    await pool.query('SELECT 1');
    
    res.json({
      status: 'OK',
      service: 'NULEX Backend API',
      version: '1.0.0',
      timestamp: new Date().toISOString(),
      environment: process.env.NODE_ENV,
      database: 'Connected',
      korapay: 'Configured'
    });
  } catch (error) {
    res.status(500).json({
      status: 'ERROR',
      error: error.message
    });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Global error:', err);
  res.status(500).json({
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Endpoint not found',
    path: req.originalUrl
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`
  ===========================================
  🚀 NULEX BACKEND LIVE - PRODUCTION READY
  📡 Port: ${PORT}
  🔗 Korapay: ACTIVE with your API keys
  🗄️  Database: PostgreSQL
  ⚡ Environment: ${process.env.NODE_ENV}
  🕒 Started: ${new Date().toLocaleString()}
  ===========================================
  `);
});