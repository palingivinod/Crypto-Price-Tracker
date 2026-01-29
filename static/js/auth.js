// Authentication JavaScript
document.addEventListener('DOMContentLoaded', function() {
    // Global alert function
    window.showAlert = function(type, message, duration = 5000) {
        // Create alert container if it doesn't exist
        let container = document.getElementById('alert-container');
        if (!container) {
            container = document.createElement('div');
            container.id = 'alert-container';
            container.className = 'alert-container';
            document.body.appendChild(container);
        }
        
        // Create alert message
        const alertDiv = document.createElement('div');
        alertDiv.className = `alert-message ${type}`;
        alertDiv.innerHTML = `
            <span>${message}</span>
            <button class="alert-close" onclick="this.parentElement.remove()">&times;</button>
        `;
        
        container.appendChild(alertDiv);
        
        // Auto-remove after duration
        setTimeout(() => {
            if (alertDiv.parentNode) {
                alertDiv.style.animation = 'slideOut 0.3s ease';
                setTimeout(() => alertDiv.remove(), 300);
            }
        }, duration);
    };

    // Handle form submissions
    const loginForm = document.querySelector('form[action="/login"]');
    const registerForm = document.querySelector('form[action="/register"]');
    
    if (loginForm) {
        loginForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            await handleAuthForm(this, '/login');
        });
    }
    
    if (registerForm) {
        registerForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            await handleAuthForm(this, '/register');
        });
    }
    
    async function handleAuthForm(form, endpoint) {
        const submitBtn = form.querySelector('button[type="submit"]');
        const originalText = submitBtn.innerHTML;
        
        // Show loading
        submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Processing...';
        submitBtn.disabled = true;
        
        try {
            const formData = new FormData(form);
            const data = Object.fromEntries(formData);
            
            const response = await fetch(endpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(data)
            });
            
            const result = await response.json();
            
            if (result.success) {
                showAlert('success', result.message);
                
                if (result.redirect) {
                    setTimeout(() => {
                        window.location.href = result.redirect;
                    }, 1500);
                }
            } else {
                showAlert('error', result.message || 'Authentication failed');
                submitBtn.innerHTML = originalText;
                submitBtn.disabled = false;
            }
        } catch (error) {
            showAlert('error', 'Network error. Please try again.');
            submitBtn.innerHTML = originalText;
            submitBtn.disabled = false;
        }
    }
    
    // Password toggle functionality
    const passwordToggles = document.querySelectorAll('.password-toggle');
    passwordToggles.forEach(toggle => {
        toggle.addEventListener('click', function() {
            const input = this.parentElement.querySelector('input');
            const icon = this.querySelector('i');
            
            if (input.type === 'password') {
                input.type = 'text';
                icon.classList.remove('fa-eye');
                icon.classList.add('fa-eye-slash');
            } else {
                input.type = 'password';
                icon.classList.remove('fa-eye-slash');
                icon.classList.add('fa-eye');
            }
        });
    });
    
    // Demo credentials button
    const demoBtn = document.createElement('button');
    demoBtn.type = 'button';
    demoBtn.className = 'btn btn-secondary';
    demoBtn.style.cssText = `
        width: 100%;
        margin-top: 15px;
        padding: 12px;
        background: #8b5cf6;
        color: white;
        border: none;
        border-radius: 12px;
        font-weight: 600;
        cursor: pointer;
    `;
    demoBtn.innerHTML = '<i class="fas fa-magic"></i> Try Demo Account';
    demoBtn.onclick = () => {
        const emailInput = document.querySelector('input[type="email"]');
        const passwordInput = document.querySelector('input[type="password"]');
        
        if (emailInput && passwordInput) {
            emailInput.value = 'demo@cryptotracker.com';
            passwordInput.value = 'demo123';
            showAlert('info', 'Demo credentials filled. Click Login to continue.');
        }
    };
    
    // Add demo button to login form
    if (loginForm) {
        loginForm.appendChild(demoBtn);
    }
});