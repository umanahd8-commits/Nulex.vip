-- Run this in your PostgreSQL database

-- 1. Create database
CREATE DATABASE nulex_db;

-- 2. Connect to nulex_db and run:

-- Users table
CREATE TABLE users (
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

-- Packages table
CREATE TABLE packages (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) NOT NULL,
    amount DECIMAL(15,2) NOT NULL,
    referral_commission DECIMAL(15,2) NOT NULL,
    description TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Investments table
CREATE TABLE investments (
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

-- Transactions table
CREATE TABLE transactions (
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

-- Withdrawals table
CREATE TABLE withdrawals (
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

-- Engagement tasks table
CREATE TABLE engagement_tasks (
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

-- Referral commissions table
CREATE TABLE referral_commissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    referrer_id UUID REFERENCES users(id) ON DELETE CASCADE,
    referred_id UUID REFERENCES users(id) ON DELETE CASCADE,
    investment_id UUID REFERENCES investments(id),
    amount DECIMAL(15,2) NOT NULL,
    status VARCHAR(20) DEFAULT 'pending',
    paid_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Insert default packages
INSERT INTO packages (name, amount, referral_commission, description) VALUES
('Elite Package', 4500.00, 2000.00, 'Perfect for beginners with daily returns'),
('Platinum Package', 7500.00, 3500.00, 'Premium package with higher returns and VIP support');

-- Create admin user (password: Admin@1234)
INSERT INTO users (email, password_hash, full_name, referral_code, role, has_deposited, balance, is_active) 
VALUES (
    'admin@nulex.com',
    '$2a$10$N9qo8uLOickgx2ZMRZoMy.Mr7c6LwL5/5CQz6KJQ6YjZG.3JzqY8W', -- Hashed 'Admin@1234'
    'NULEX Admin',
    'ADMIN' || substring(md5(random()::text), 1, 5),
    'admin',
    TRUE,
    1000000,
    TRUE
);

-- Create indexes for performance
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_referral_code ON users(referral_code);
CREATE INDEX idx_transactions_user_id ON transactions(user_id);
CREATE INDEX idx_transactions_reference ON transactions(reference);
CREATE INDEX idx_investments_user_id ON investments(user_id);
CREATE INDEX idx_withdrawals_status ON withdrawals(status);
CREATE INDEX idx_referral_commissions_referrer_id ON referral_commissions(referrer_id);