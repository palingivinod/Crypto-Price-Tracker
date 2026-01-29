// // Alerts management functionality
// document.addEventListener('DOMContentLoaded', function() {
//     loadAlerts();
//     setupAlertForm();
//     setupAlertActions();
// });

// function loadAlerts() {
//     // Fetch alerts from API
//     fetch('/api/alerts')
//         .then(response => {
//             if (!response.ok) throw new Error('Network response was not ok');
//             return response.json();
//         })
//         .then(alerts => {
//             displayAlerts(alerts);
//         })
//         .catch(error => {
//             console.error('Error loading alerts:', error);
//             // For demo, use sample data
//             const sampleAlerts = getSampleAlerts();
//             displayAlerts(sampleAlerts);
//         });
// }

// function getSampleAlerts() {
//     return [
//         {
//             id: '1',
//             coin: 'BTC',
//             coinName: 'Bitcoin',
//             condition: 'above',
//             targetPrice: 70000,
//             currentPrice: 64328.45,
//             status: 'active',
//             createdAt: '2024-01-20T10:30:00Z'
//         },
//         {
//             id: '2',
//             coin: 'ETH',
//             coinName: 'Ethereum',
//             condition: 'below',
//             targetPrice: 3000,
//             currentPrice: 3245.67,
//             status: 'active',
//             createdAt: '2024-01-19T14:20:00Z'
//         },
//         {
//             id: '3',
//             coin: 'SOL',
//             coinName: 'Solana',
//             condition: 'above',
//             targetPrice: 200,
//             currentPrice: 215.50,
//             status: 'triggered',
//             createdAt: '2024-01-18T09:15:00Z'
//         }
//     ];
// }

// function displayAlerts(alerts) {
//     const container = document.querySelector('.alerts-list');
//     if (!container) return;
    
//     container.innerHTML = '';
    
//     alerts.forEach(alert => {
//         const alertElement = createAlertElement(alert);
//         container.appendChild(alertElement);
//     });
    
//     // Update stats
//     updateAlertStats(alerts);
// }

// function createAlertElement(alert) {
//     const element = document.createElement('div');
//     element.className = 'alert-item';
//     element.dataset.id = alert.id;
    
//     const icon = getCoinIcon(alert.coin);
//     const statusClass = alert.status === 'triggered' ? 'triggered' : 'active';
//     const priceDiff = alert.currentPrice - alert.targetPrice;
//     const progress = calculateProgress(alert);
    
//     element.innerHTML = `
//         <div class="alert-info">
//             ${icon}
//             <div>
//                 <span class="alert-coin">${alert.coinName} (${alert.coin})</span>
//                 <br>
//                 <span>Alert when price <strong>${alert.condition === 'above' ? 'goes above' : 'goes below'}</strong></span>
//                 <span class="alert-price"> $${alert.targetPrice.toLocaleString()}</span>
//                 <div style="margin-top: 8px; font-size: 0.9rem; color: #94a3b8;">
//                     Current: $${alert.currentPrice.toLocaleString()} 
//                     <span style="color: ${priceDiff >= 0 ? '#10b981' : '#ef4444'}; margin-left: 10px;">
//                         ${priceDiff >= 0 ? '+' : ''}${priceDiff.toFixed(2)} (${(priceDiff/alert.targetPrice*100).toFixed(2)}%)
//                     </span>
//                 </div>
//                 <div class="progress-bar" style="margin-top: 10px; height: 4px; background: #334155; border-radius: 2px;">
//                     <div class="progress-fill" style="height: 100%; width: ${progress}%; background: ${getProgressColor(progress)}; border-radius: 2px;"></div>
//                 </div>
//             </div>
//         </div>
//         <div class="alert-status ${statusClass}">${alert.status.charAt(0).toUpperCase() + alert.status.slice(1)}</div>
//         <div class="alert-actions">
//             <button class="btn btn-secondary btn-sm" onclick="editAlert('${alert.id}')">
//                 <i class="fas fa-edit"></i>
//             </button>
//             <button class="btn btn-danger btn-sm" onclick="deleteAlert('${alert.id}')">
//                 <i class="fas fa-trash"></i>
//             </button>
//         </div>
//     `;
    
//     return element;
// }

// function getCoinIcon(coin) {
//     const icons = {
//         'BTC': '<i class="fas fa-bitcoin text-primary" style="font-size: 1.5rem;"></i>',
//         'ETH': '<i class="fab fa-ethereum text-primary" style="font-size: 1.5rem;"></i>',
//         'SOL': '<i class="fas fa-fire text-warning" style="font-size: 1.5rem;"></i>',
//         'ADA': '<i class="fab fa-ada-cardano text-primary" style="font-size: 1.5rem;"></i>',
//         'XRP': '<i class="fas fa-bolt text-primary" style="font-size: 1.5rem;"></i>'
//     };
//     return icons[coin] || '<i class="fas fa-coins text-primary" style="font-size: 1.5rem;"></i>';
// }

// function calculateProgress(alert) {
//     // Calculate how close current price is to target
//     const current = alert.currentPrice;
//     const target = alert.targetPrice;
    
//     // For demo purposes, use random progress
//     // In production, calculate based on price movement
//     return Math.min(Math.random() * 100, 100);
// }

// function getProgressColor(progress) {
//     if (progress >= 90) return '#10b981'; // Green
//     if (progress >= 70) return '#38bdf8'; // Blue
//     if (progress >= 50) return '#f59e0b'; // Yellow
//     return '#ef4444'; // Red
// }

// function updateAlertStats(alerts) {
//     const activeAlerts = alerts.filter(a => a.status === 'active').length;
//     const triggeredAlerts = alerts.filter(a => a.status === 'triggered').length;
    
//     const statsElement = document.querySelector('.alert-stats');
//     if (!statsElement) return;
    
//     statsElement.innerHTML = `
//         <div style="display: flex; gap: 20px;">
//             <div>
//                 <div style="font-size: 2rem; font-weight: bold; color: #38bdf8;">${activeAlerts}</div>
//                 <div style="color: #94a3b8;">Active Alerts</div>
//             </div>
//             <div>
//                 <div style="font-size: 2rem; font-weight: bold; color: #ef4444;">${triggeredAlerts}</div>
//                 <div style="color: #94a3b8;">Triggered</div>
//             </div>
//             <div>
//                 <div style="font-size: 2rem; font-weight: bold; color: #10b981;">${alerts.length}</div>
//                 <div style="color: #94a3b8;">Total</div>
//             </div>
//         </div>
//     `;
// }

// function setupAlertForm() {
//     const form = document.querySelector('form');
//     if (!form) return;
    
//     form.addEventListener('submit', function(e) {
//         e.preventDefault();
        
//         const formData = new FormData(this);
//         const alertData = {
//             coin: formData.get('coin'),
//             condition: formData.get('condition'),
//             price: parseFloat(formData.get('price'))
//         };
        
//         // Validate
//         if (!alertData.coin || !alertData.price) {
//             showAlertMessage('Please fill in all required fields', 'error');
//             return;
//         }
        
//         // Submit to API
//         submitAlert(alertData);
//     });
    
//     // Real-time price display
//     const priceInput = document.querySelector('input[name="price"]');
//     if (priceInput) {
//         priceInput.addEventListener('input', function() {
//             updatePricePreview(this.value);
//         });
//     }
// }

// function updatePricePreview(price) {
//     const preview = document.getElementById('price-preview');
//     if (!preview) return;
    
//     if (price) {
//         preview.textContent = `Alert at: $${parseFloat(price).toLocaleString()}`;
//         preview.style.display = 'block';
//     } else {
//         preview.style.display = 'none';
//     }
// }

// function submitAlert(alertData) {
//     // Show loading
//     showLoading('Creating alert...');
    
//     // Simulate API call
//     setTimeout(() => {
//         // In production, replace with actual fetch call
//         // fetch('/api/alerts', {
//         //     method: 'POST',
//         //     headers: { 'Content-Type': 'application/json' },
//         //     body: JSON.stringify(alertData)
//         // })
        
//         // For demo
//         const newAlert = {
//             id: Date.now().toString(),
//             coin: alertData.coin,
//             coinName: getCoinName(alertData.coin),
//             condition: alertData.condition,
//             targetPrice: alertData.price,
//             currentPrice: getCurrentPrice(alertData.coin),
//             status: 'active',
//             createdAt: new Date().toISOString()
//         };
        
//         // Add to list
//         addAlertToList(newAlert);
        
//         // Reset form
//         document.querySelector('form').reset();
//         document.getElementById('alertForm').style.display = 'none';
        
//         // Show success message
//         showAlertMessage('Alert created successfully!', 'success');
        
//         hideLoading();
//     }, 1000);
// }

// function getCoinName(symbol) {
//     const coins = {
//         'bitcoin': 'Bitcoin',
//         'ethereum': 'Ethereum',
//         'solana': 'Solana',
//         'cardano': 'Cardano',
//         'ripple': 'Ripple'
//     };
//     return coins[symbol] || symbol;
// }

// function getCurrentPrice(coin) {
//     // Simulated current prices
//     const prices = {
//         'bitcoin': 64328.45,
//         'ethereum': 3245.67,
//         'solana': 215.50,
//         'cardano': 0.58,
//         'ripple': 0.52
//     };
//     return prices[coin] || 0;
// }

// function addAlertToList(alert) {
//     const container = document.querySelector('.alerts-list');
//     const alertElement = createAlertElement(alert);
//     container.insertBefore(alertElement, container.firstChild);
    
//     // Update stats
//     loadAlerts(); // Reload to update stats
// }

// function setupAlertActions() {
//     // Delete confirmation
//     window.deleteAlert = function(id) {
//         if (confirm('Are you sure you want to delete this alert?')) {
//             // Show loading
//             showLoading('Deleting alert...');
            
//             // Simulate API call
//             setTimeout(() => {
//                 // In production: fetch(`/api/alerts/${id}`, { method: 'DELETE' })
                
//                 // Remove from DOM
//                 const element = document.querySelector(`[data-id="${id}"]`);
//                 if (element) {
//                     element.style.opacity = '0';
//                     element.style.transform = 'translateX(100px)';
                    
//                     setTimeout(() => {
//                         element.remove();
//                         loadAlerts(); // Reload to update stats
//                         showAlertMessage('Alert deleted successfully', 'success');
//                     }, 300);
//                 }
                
//                 hideLoading();
//             }, 500);
//         }
//     };
    
//     // Edit alert
//     window.editAlert = function(id) {
//         // In production, fetch alert data and populate form
//         showAlertMessage('Edit functionality would load here', 'info');
//     };
// }

// function showAlertForm() {
//     document.getElementById('alertForm').style.display = 'block';
//     document.getElementById('alertForm').scrollIntoView({ behavior: 'smooth' });
// }

// function showAlertMessage(message, type = 'info') {
//     const alertDiv = document.createElement('div');
//     alertDiv.className = `alert-message ${type}`;
//     alertDiv.innerHTML = `
//         <div style="display: flex; align-items: center; justify-content: space-between;">
//             <span>${message}</span>
//             <button onclick="this.parentElement.parentElement.remove()" style="background: none; border: none; color: inherit; cursor: pointer;">
//                 <i class="fas fa-times"></i>
//             </button>
//         </div>
//     `;
    
//     alertDiv.style.cssText = `
//         position: fixed;
//         top: 20px;
//         right: 20px;
//         padding: 15px 20px;
//         background: ${type === 'success' ? '#10b981' : type === 'error' ? '#ef4444' : '#38bdf8'};
//         color: white;
//         border-radius: 8px;
//         box-shadow: 0 5px 15px rgba(0,0,0,0.2);
//         z-index: 1000;
//         animation: slideIn 0.3s ease;
//     `;
    
//     document.body.appendChild(alertDiv);
    
//     setTimeout(() => {
//         alertDiv.style.animation = 'slideOut 0.3s ease';
//         setTimeout(() => alertDiv.remove(), 300);
//     }, 3000);
// }

// function showLoading(message = 'Loading...') {
//     let loader = document.getElementById('loading');
//     if (!loader) {
//         loader = document.createElement('div');
//         loader.id = 'loading';
//         loader.style.cssText = `
//             position: fixed;
//             top: 0;
//             left: 0;
//             right: 0;
//             bottom: 0;
//             background: rgba(15, 23, 42, 0.9);
//             display: flex;
//             flex-direction: column;
//             justify-content: center;
//             align-items: center;
//             z-index: 9999;
//         `;
//         loader.innerHTML = `
//             <div style="width: 50px; height: 50px; border: 3px solid #38bdf8; border-top-color: transparent; border-radius: 50%; animation: spin 1s linear infinite;"></div>
//             <p style="margin-top: 20px; color: #38bdf8; font-size: 1.1rem;">${message}</p>
//         `;
//         document.body.appendChild(loader);
//     }
// }

// function hideLoading() {
//     const loader = document.getElementById('loading');
//     if (loader) {
//         loader.style.opacity = '0';
//         setTimeout(() => loader.remove(), 300);
//     }
// }

// // Add CSS animations
// const style = document.createElement('style');
// style.textContent = `
//     @keyframes slideIn {
//         from { transform: translateX(100%); opacity: 0; }
//         to { transform: translateX(0); opacity: 1; }
//     }
    
//     @keyframes slideOut {
//         from { transform: translateX(0); opacity: 1; }
//         to { transform: translateX(100%); opacity: 0; }
//     }
    
//     @keyframes spin {
//         to { transform: rotate(360deg); }
//     }
    
//     .alert-message {
//         animation: slideIn 0.3s ease;
//     }
// `;
// document.head.appendChild(style);

document.addEventListener('DOMContentLoaded', function () {
    loadAlerts();
    setupAlertForm();
    setupAlertActions();
});

// ================= LOAD ALERTS =================
function loadAlerts() {
    fetch('/alerts/data')
        .then(res => res.json())
        .then(alerts => {
            displayAlerts(alerts);
        })
        .catch(err => console.error('Load alerts error:', err));
}

// ================= FORM SETUP =================
function setupAlertForm() {
    const form = document.querySelector('form');
    if (!form) return;

    form.addEventListener('submit', function (e) {
        e.preventDefault();

        const formData = new FormData(this);
        const alertData = {
            coin: formData.get('coin'),
            condition: formData.get('condition'),
            price: parseFloat(formData.get('price'))
        };

        submitAlert(alertData);
    });
}

// ================= HELPER FUNCTIONS =================

function updateAlertStats(alerts) {
    // Safe no-op stats updater
    const stats = document.querySelector('.alert-stats');
    if (!stats) return;
}

function showLoading(message = 'Loading...') {
    let loader = document.getElementById('loading');
    if (!loader) {
        loader = document.createElement('div');
        loader.id = 'loading';
        loader.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(15, 23, 42, 0.9);
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            z-index: 9999;
        `;
        loader.innerHTML = `
            <div style="width: 50px; height: 50px; border: 3px solid #38bdf8;
                        border-top-color: transparent; border-radius: 50%;
                        animation: spin 1s linear infinite;"></div>
            <p style="margin-top: 20px; color: #38bdf8;">${message}</p>
        `;
        document.body.appendChild(loader);
    }
}

function hideLoading() {
    const loader = document.getElementById('loading');
    if (loader) loader.remove();
}

function showAlertMessage(message, type = 'info') {
    alert(message); // simple + safe (no UI break)
}


// ================= CREATE ALERT =================
function submitAlert(alertData) {
    showLoading('Creating alert...');

    fetch('/alerts/data', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(alertData)
    })
        .then(res => res.json())
        .then(() => {
            hideLoading();
            loadAlerts();
            showAlertMessage('Alert created successfully', 'success');
            document.querySelector('form').reset();
        })
        .catch(() => {
            hideLoading();
            showAlertMessage('Failed to create alert', 'error');
        });
}

// ================= DISPLAY ALERTS =================

function createAlertElement(alert) {
    const div = document.createElement('div');
    div.className = 'alert-item';
    div.dataset.id = alert.id;

    div.innerHTML = `
        <div class="alert-info">
            <i class="fas fa-bell text-primary"></i>
            <div>
                <span class="alert-coin">${alert.coinName}</span><br>
                <span>
                    Alert when price <strong>${alert.condition === 'above' ? 'goes above' : 'goes below'}</strong>
                </span>
                <span class="alert-price"> $${alert.price}</span>
            </div>
        </div>
        <div class="alert-status active">Active</div>
        <div class="alert-actions">
            <button class="btn btn-secondary btn-sm" onclick="editAlert('${alert.id}')">
                <i class="fas fa-edit"></i>
            </button>
            <button class="btn btn-danger btn-sm" onclick="deleteAlert('${alert.id}')">
                <i class="fas fa-trash"></i>
            </button>
        </div>
    `;

    return div;
}


function displayAlerts(alerts) {
    const container = document.querySelector('.alerts-list');
    if (!container) return;

    container.innerHTML = '';

    alerts.forEach(alert => {
        const el = createAlertElement({
            ...alert,
            coinName: alert.coin.toUpperCase(),
            currentPrice: '-',
            status: 'active'
        });
        container.appendChild(el);
    });

    updateAlertStats(alerts);
}

// ================= DELETE & UPDATE =================
function setupAlertActions() {

    window.deleteAlert = function (id) {
        if (!confirm('Delete this alert?')) return;

        showLoading('Deleting alert...');

        fetch(`/alerts/data/${id}`, {
            method: 'DELETE'
        })
            .then(res => res.json())
            .then(() => {
                hideLoading();
                loadAlerts();
                showAlertMessage('Alert deleted successfully', 'success');
            })
            .catch(() => {
                hideLoading();
                showAlertMessage('Delete failed', 'error');
            });
    };

    window.editAlert = function (id) {
        const newPrice = prompt('Enter new target price');
        if (!newPrice) return;

        fetch(`/alerts/data/${id}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                price: parseFloat(newPrice),
                condition: 'below'
            })
        })
            .then(res => res.json())
            .then(() => {
                loadAlerts();
                showAlertMessage('Alert updated successfully', 'success');
            })
            .catch(() => {
                showAlertMessage('Update failed', 'error');
            });
    };
}

