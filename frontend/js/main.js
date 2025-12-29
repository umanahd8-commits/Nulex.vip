// REAL API Configuration
const API_BASE_URL = 'https://your-backend-url.com/api'; // Your Render backend URL

// Real API Functions
async function registerUser(userData) {
    const response = await fetch(`${API_BASE_URL}/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(userData)
    });
    return await response.json();
}

async function loginUser(credentials) {
    const response = await fetch(`${API_BASE_URL}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(credentials)
    });
    return await response.json();
}

async function verifyBankAccount(accountData, token) {
    const response = await fetch(`${API_BASE_URL}/bank/verify`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(accountData)
    });
    return await response.json();
}

async function initializePayment(paymentData, token) {
    const response = await fetch(`${API_BASE_URL}/payment/initialize`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(paymentData)
    });
    return await response.json();
}

async function requestWithdrawal(withdrawalData, token) {
    const response = await fetch(`${API_BASE_URL}/withdraw`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(withdrawalData)
    });
    return await response.json();
}

// REAL Payment Integration Example
async function processInvestment(packageId, amount) {
    const token = localStorage.getItem('token');
    const user = JSON.parse(localStorage.getItem('user'));
    
    if (!token || !user) {
        alert('Please login first');
        return;
    }
    
    try {
        // Initialize Korapay payment
        const payment = await initializePayment({
            amount: amount,
            packageId: packageId
        }, token);
        
        if (payment.success) {
            // Redirect to Korapay checkout page
            window.location.href = payment.payment_url;
        } else {
            alert('Payment initialization failed: ' + payment.error);
        }
    } catch (error) {
        console.error('Payment error:', error);
        alert('Payment processing failed');
    }
}

// REAL Bank Verification Example
async function verifyBank() {
    const accountNumber = document.getElementById('accountNumber').value;
    const bankCode = document.getElementById('bankSelect').value;
    const token = localStorage.getItem('token');
    
    if (!accountNumber || !bankCode) {
        alert('Please fill all fields');
        return;
    }
    
    try {
        const verification = await verifyBankAccount({
            accountNumber: accountNumber,
            bankCode: bankCode
        }, token);
        
        if (verification.success) {
            document.getElementById('verifiedName').textContent = verification.data.account_name;
            document.getElementById('verifiedBank').textContent = verification.data.bank_name;
            document.getElementById('verificationResult').style.display = 'block';
        } else {
            alert('Bank verification failed: ' + verification.error);
        }
    } catch (error) {
        console.error('Verification error:', error);
        alert('Bank verification failed');
    }
}

// REAL Withdrawal Example
async function submitWithdrawal() {
    const amount = parseFloat(document.getElementById('withdrawAmount').value);
    const token = localStorage.getItem('token');
    
    if (amount < 1000) {
        alert('Minimum withdrawal is ₦1000');
        return;
    }
    
    try {
        const withdrawal = await requestWithdrawal({ amount: amount }, token);
        
        if (withdrawal.message) {
            alert(withdrawal.message);
            // Update balance display
            updateUserBalance();
        } else {
            alert('Withdrawal failed: ' + withdrawal.error);
        }
    } catch (error) {
        console.error('Withdrawal error:', error);
        alert('Withdrawal request failed');
    }
}

// Update all your event listeners to use REAL API calls
document.addEventListener('DOMContentLoaded', function() {
    // Replace all mock calls with real API calls
    // Your existing frontend code, but now using the real API functions above
});