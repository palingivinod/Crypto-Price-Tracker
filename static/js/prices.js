// fetch("/api/prices")
// .then(res => res.json())
// .then(data => {
//     document.getElementById("btc").innerText = "$" + data.bitcoin;
//     document.getElementById("eth").innerText = "$" + data.ethereum;
// });
// Live cryptocurrency price updates with simulation
document.addEventListener('DOMContentLoaded', function() {
    // Initialize prices
    updatePrices();
    
    // Update prices every 5 seconds
    setInterval(updatePrices, 5000);
    
    // Time filter functionality
    setupTimeFilters();
    
    // Load prediction data
    loadPredictions();
});
// Fetch live prices from Flask API (CoinGecko → backend)
function loadPrices() {
    fetch("/prices")
        .then(res => res.json())
        .then(data => {
            document.getElementById("btc-price").innerText = "$ " + data.bitcoin;
            document.getElementById("eth-price").innerText = "$ " + data.ethereum;
        })
        .catch(err => {
            console.error("Price fetch error:", err);
        });
}

// Load immediately
loadPrices();

// Refresh every 15 seconds (real-time feel)
setInterval(loadPrices, 15000);

function updatePrices() {
    fetch("/prices")
        .then(res => res.json())
        .then(apiData => {

            const prices = {
                btc: {
                    price: apiData.bitcoin.toFixed(2),
                    change: 0,        // keeping same key (you can calculate later)
                    high: apiData.bitcoin.toFixed(2),
                    low: apiData.bitcoin.toFixed(2),
                    volume: "N/A"
                },
                eth: {
                    price: apiData.ethereum.toFixed(2),
                    change: 0,        // keeping same key
                    high: apiData.ethereum.toFixed(2),
                    low: apiData.ethereum.toFixed(2),
                    volume: "N/A"
                }
            };

            // Update Bitcoin
            updateCryptoCard('btc', prices.btc);

            // Update Ethereum
            updateCryptoCard('eth', prices.eth);

            // Keep animation exactly as before
            animatePriceChange();
        })
        .catch(err => {
            console.error("Price fetch error:", err);
        });
}


function updateCryptoCard(crypto, data) {
    const priceElement = document.getElementById(crypto);
    const oldPrice = parseFloat(priceElement.textContent.replace(/[^0-9.-]+/g, ""));
    const newPrice = parseFloat(data.price);
    
    // Update price with animation
    priceElement.classList.remove('price-up', 'price-down');
    if (newPrice > oldPrice) {
        priceElement.classList.add('price-up');
    } else if (newPrice < oldPrice) {
        priceElement.classList.add('price-down');
    }
    
    priceElement.textContent = `$${data.price}`;
    
    // Update change indicator
    const changeElement = priceElement.closest('.crypto-card').querySelector('.price-change');
    const isPositive = parseFloat(data.change) >= 0;
    
    changeElement.innerHTML = isPositive ? 
        `<i class="fas fa-arrow-up"></i> +${Math.abs(data.change)}%` :
        `<i class="fas fa-arrow-down"></i> -${Math.abs(data.change)}%`;
    
    changeElement.className = `price-change ${isPositive ? 'positive' : 'negative'}`;
    
    // Update stats
    const statsContainer = priceElement.closest('.crypto-card').querySelector('.price-stats');
    statsContainer.querySelectorAll('.stat-item')[0].querySelector('.stat-value').textContent = `$${data.high}`;
    statsContainer.querySelectorAll('.stat-item')[1].querySelector('.stat-value').textContent = `$${data.low}`;
    statsContainer.querySelectorAll('.stat-item')[2].querySelector('.stat-value').textContent = `$${data.volume}`;
}

function animatePriceChange() {
    // Add visual feedback for price changes
    document.querySelectorAll('.crypto-card').forEach(card => {
        card.style.transition = 'all 0.3s';
        card.style.boxShadow = '0 5px 15px rgba(56, 189, 248, 0.2)';
        
        setTimeout(() => {
            card.style.boxShadow = '';
        }, 300);
    });
}

function setupTimeFilters() {
    document.querySelectorAll('.time-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            // Remove active class from all buttons
            document.querySelectorAll('.time-btn').forEach(b => b.classList.remove('active'));
            
            // Add active class to clicked button
            this.classList.add('active');
            
            // Load data for selected time period
            const period = this.textContent;
            loadTimePeriodData(period);
            
            // Show loading state
            showLoading();
        });
    });
}

function loadTimePeriodData(period) {
    // Simulate API call for time period data
    const predictions = {
        '24H': { price: '65,200 ± 800', confidence: 75 },
        '7D': { price: '68,450 ± 1,200', confidence: 85 },
        '1M': { price: '72,000 ± 2,500', confidence: 70 },
        '1Y': { price: '85,000 ± 5,000', confidence: 65 }
    };
    
    // Update prediction cards
    const predictionCard = document.querySelector('.prediction-card');
    if (predictionCard) {
        const prediction = predictions[period] || predictions['7D'];
        predictionCard.querySelector('.prediction-value').textContent = `$${prediction.price}`;
        predictionCard.querySelector('.confidence-fill').style.width = `${prediction.confidence}%`;
        predictionCard.querySelector('p').textContent = `Confidence: ${prediction.confidence}% - ${getPredictionText(prediction.confidence)}`;
    }
    
    // Hide loading after delay
    setTimeout(hideLoading, 500);
}

function getPredictionText(confidence) {
    if (confidence >= 80) return 'Strong Buy Signal';
    if (confidence >= 60) return 'Buy Signal';
    if (confidence >= 40) return 'Neutral';
    return 'Caution Advised';
}

function loadPredictions() {
    // Simulated AI predictions
    const predictions = [
        {
            coin: 'BTC',
            prediction: '$68,450 ± $1,200',
            confidence: 85,
            timeframe: '7 days',
            trend: 'bullish'
        },
        {
            coin: 'ETH',
            prediction: '$3,500 ± $150',
            confidence: 78,
            timeframe: '7 days',
            trend: 'bullish'
        }
    ];
    
    // Display predictions
    const container = document.querySelector('.prediction-cards');
    if (container) {
        predictions.forEach(pred => {
            const card = createPredictionCard(pred);
            container.appendChild(card);
        });
    }
}

function createPredictionCard(pred) {
    const card = document.createElement('div');
    card.className = 'prediction-card';
    card.innerHTML = `
        <div class="prediction-header">
            <i class="fas fa-robot"></i>
            <h3>${pred.coin} Prediction (${pred.timeframe})</h3>
        </div>
        <div class="prediction-value">${pred.prediction}</div>
        <div class="confidence-meter">
            <div class="confidence-fill" style="width: ${pred.confidence}%"></div>
        </div>
        <p>Confidence: ${pred.confidence}% - ${pred.trend.toUpperCase()}</p>
        <div style="margin-top: 15px; font-size: 0.9rem; color: #94a3b8;">
            <i class="fas fa-info-circle"></i> Based on ML model v4.2
        </div>
    `;
    return card;
}

function showLoading() {
    // Create loading overlay
    let loader = document.getElementById('loading-overlay');
    if (!loader) {
        loader = document.createElement('div');
        loader.id = 'loading-overlay';
        loader.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(15, 23, 42, 0.9);
            display: flex;
            justify-content: center;
            align-items: center;
            z-index: 9999;
        `;
        loader.innerHTML = `
            <div class="loading-spinner">
                <div style="width: 50px; height: 50px; border: 3px solid #38bdf8; border-top-color: transparent; border-radius: 50%; animation: spin 1s linear infinite;"></div>
                <p style="margin-top: 20px; color: #38bdf8;">Loading data...</p>
            </div>
        `;
        document.body.appendChild(loader);
    }
}

function hideLoading() {
    const loader = document.getElementById('loading-overlay');
    if (loader) {
        loader.remove();
    }
}

// WebSocket for real-time updates (simulated)
function setupWebSocket() {
    // In production, connect to actual WebSocket server
    console.log('WebSocket would connect here for real-time updates');
    
    // Simulate periodic updates
    setInterval(() => {
        // Simulate price alerts
        if (Math.random() > 0.7) {
            showNotification('Price Alert', 'Bitcoin crossed $65,000!', 'info');
        }
    }, 10000);
}

function showNotification(title, message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `
        <div style="display: flex; align-items: center; gap: 10px;">
            <i class="fas fa-bell" style="color: #38bdf8;"></i>
            <div>
                <strong>${title}</strong>
                <p style="margin: 5px 0 0; font-size: 0.9rem;">${message}</p>
            </div>
        </div>
    `;
    
    document.body.appendChild(toast);
    
    setTimeout(() => {
        toast.classList.add('show');
    }, 100);
    
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 300);
    }, 5000);
}

setupWebSocket();