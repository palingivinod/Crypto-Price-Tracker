
document.addEventListener('DOMContentLoaded', function() {
    initializeChart();
    setupTimeFilters();
    setupCoinSelector();
    loadHistoricalData();
});

let cryptoChart;

function initializeChart() {
    const ctx = document.getElementById('cryptoChart').getContext('2d');
    
    cryptoChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Price (USD)',
                data: [],
                borderColor: '#38bdf8',
                backgroundColor: 'rgba(56, 189, 248, 0.1)',
                borderWidth: 3,
                fill: true,
                tension: 0.4,
                pointRadius: 0,
                pointHoverRadius: 6
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: {
                intersect: false,
                mode: 'index',
            },
            plugins: {
                legend: {
                    display: true,
                    labels: {
                        color: '#e5e7eb',
                        font: {
                            size: 14
                        }
                    }
                },
                tooltip: {
                    backgroundColor: 'rgba(30, 41, 59, 0.9)',
                    titleColor: '#e5e7eb',
                    bodyColor: '#e5e7eb',
                    borderColor: '#38bdf8',
                    borderWidth: 1,
                    callbacks: {
                        label: function(context) {
                            return `$${context.parsed.y.toLocaleString()}`;
                        }
                    }
                }
            },
            scales: {
                x: {
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)',
                        borderColor: 'rgba(255, 255, 255, 0.1)'
                    },
                    ticks: {
                        color: '#94a3b8'
                    }
                },
                y: {
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)',
                        borderColor: 'rgba(255, 255, 255, 0.1)'
                    },
                    ticks: {
                        color: '#94a3b8',
                        callback: function(value) {
                            return '$' + value.toLocaleString();
                        }
                    }
                }
            }
        }
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
            loadChartData(period);
        });
    });
}

function setupCoinSelector() {
    document.querySelectorAll('.coin-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            // Remove active class from all buttons
            document.querySelectorAll('.coin-btn').forEach(b => b.classList.remove('active'));
            
            // Add active class to clicked button
            this.classList.add('active');
            
            // Load data for selected coin
            const coin = this.textContent;
            loadCoinData(coin);
        });
    });
}

function loadHistoricalData() {
    // Load default data (BTC, 1W)
    loadChartData('1W');
}

function loadChartData(timePeriod) {
    showLoading('Loading historical data...');
    
    // Simulate API call
    setTimeout(() => {
        const { labels, data } = generateHistoricalData(timePeriod);
        
        cryptoChart.data.labels = labels;
        cryptoChart.data.datasets[0].data = data;
        cryptoChart.update();
        
        updateStats(data);
        hideLoading();
    }, 800);
}

function loadCoinData(coin) {
    showLoading(`Loading ${coin} data...`);
    
    // Simulate API call
    setTimeout(() => {
        // Update chart title
        const chartTitle = document.querySelector('.chart-title');
        if (chartTitle) {
            chartTitle.textContent = `${coin} Price History`;
        }
        
        // Update chart with coin-specific data
        const timePeriod = document.querySelector('.time-btn.active')?.textContent || '1W';
        const { labels, data } = generateCoinData(coin, timePeriod);
        
        cryptoChart.data.labels = labels;
        cryptoChart.data.datasets[0].data = data;
        cryptoChart.data.datasets[0].label = `${coin} Price (USD)`;
        cryptoChart.update();
        
        updateStats(data, coin);
        hideLoading();
    }, 800);
}

function generateHistoricalData(timePeriod) {
    let labels = [];
    let data = [];
    let basePrice = 64000;
    let volatility = 0.02;
    
    // Generate data based on time period
    const periods = {
        '1W': 7,
        '1M': 30,
        '3M': 90,
        '1Y': 365,
        'ALL': 730
    };
    
    const days = periods[timePeriod] || 7;
    
    // Generate labels (dates)
    const now = new Date();
    for (let i = days - 1; i >= 0; i--) {
        const date = new Date(now);
        date.setDate(date.getDate() - i);
        
        if (days <= 30) {
            labels.push(date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }));
        } else if (days <= 90) {
            // Show every 5th day
            if (i % 5 === 0) {
                labels.push(date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }));
            } else {
                labels.push('');
            }
        } else {
            // Show month names
            if (i % 30 === 0) {
                labels.push(date.toLocaleDateString('en-US', { month: 'short', year: 'numeric' }));
            } else {
                labels.push('');
            }
        }
        
        // Generate price data with trend
        const trend = Math.sin(i / 10) * 0.5 + (i / days) * 0.3;
        const random = (Math.random() - 0.5) * 2 * volatility;
        const price = basePrice * (1 + trend + random);
        
        data.push(price);
    }
    
    return { labels, data };
}

function generateCoinData(coin, timePeriod) {
    let basePrice;
    let volatility;
    
    // Set parameters based on coin
    switch(coin) {
        case 'ETH':
            basePrice = 3200;
            volatility = 0.03;
            break;
        case 'SOL':
            basePrice = 200;
            volatility = 0.05;
            break;
        case 'ADA':
            basePrice = 0.58;
            volatility = 0.04;
            break;
        default: // BTC
            basePrice = 64000;
            volatility = 0.02;
    }
    
    const { labels, data } = generateHistoricalData(timePeriod);
    
    // Adjust data for this specific coin
    const adjustedData = data.map(price => price * (basePrice / 64000));
    
    return { labels, data: adjustedData };
}

function updateStats(data, coin = 'BTC') {
    if (data.length === 0) return;
    
    const current = data[data.length - 1];
    const previous = data[0];
    const change = ((current - previous) / previous) * 100;
    
    // Calculate high and low
    const high = Math.max(...data);
    const low = Math.min(...data);
    
    // Calculate volatility
    const returns = [];
    for (let i = 1; i < data.length; i++) {
        returns.push((data[i] - data[i-1]) / data[i-1]);
    }
    const volatility = Math.sqrt(returns.reduce((a, b) => a + b * b, 0) / returns.length) * 100;
    
    // Update stats display
    const statsContainer = document.querySelector('.performance-stats');
    if (statsContainer) {
        statsContainer.innerHTML = `
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-top: 20px;">
                <div style="background: rgba(30, 41, 59, 0.5); padding: 20px; border-radius: 12px;">
                    <div style="color: #94a3b8; font-size: 0.9rem;">Current Price</div>
                    <div style="font-size: 2rem; font-weight: bold; color: #38bdf8;">$${current.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })}</div>
                </div>
                <div style="background: rgba(30, 41, 59, 0.5); padding: 20px; border-radius: 12px;">
                    <div style="color: #94a3b8; font-size: 0.9rem;">Period Change</div>
                    <div style="font-size: 2rem; font-weight: bold; color: ${change >= 0 ? '#10b981' : '#ef4444'};">${change >= 0 ? '+' : ''}${change.toFixed(2)}%</div>
                </div>
                <div style="background: rgba(30, 41, 59, 0.5); padding: 20px; border-radius: 12px;">
                    <div style="color: #94a3b8; font-size: 0.9rem;">Period High</div>
                    <div style="font-size: 2rem; font-weight: bold; color: #10b981;">$${high.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })}</div>
                </div>
                <div style="background: rgba(30, 41, 59, 0.5); padding: 20px; border-radius: 12px;">
                    <div style="color: #94a3b8; font-size: 0.9rem;">Volatility</div>
                    <div style="font-size: 2rem; font-weight: bold; color: #f59e0b;">${volatility.toFixed(2)}%</div>
                </div>
            </div>
        `;
    }
    
    // Update prediction accuracy
    updatePredictionAccuracy(coin, change);
}

function updatePredictionAccuracy(coin, actualChange) {
    // Simulate prediction accuracy calculation
    const predictedChange = 5.2; // Example predicted change
    const accuracy = 100 - Math.abs(predictedChange - actualChange);
    
    const accuracyElement = document.querySelector('.accuracy-display');
    if (accuracyElement) {
        accuracyElement.innerHTML = `
            <div style="background: rgba(30, 41, 59, 0.5); padding: 20px; border-radius: 12px; margin-top: 20px;">
                <div style="color: #94a3b8; font-size: 0.9rem;">Prediction Accuracy</div>
                <div style="font-size: 2rem; font-weight: bold; color: ${accuracy >= 80 ? '#10b981' : accuracy >= 60 ? '#38bdf8' : '#f59e0b'};">${Math.max(0, Math.min(100, accuracy)).toFixed(1)}%</div>
                <div style="margin-top: 10px; color: #94a3b8; font-size: 0.9rem;">
                    Predicted: ${predictedChange >= 0 ? '+' : ''}${predictedChange.toFixed(1)}% | 
                    Actual: ${actualChange >= 0 ? '+' : ''}${actualChange.toFixed(1)}%
                </div>
                <div style="margin-top: 10px; height: 8px; background: #334155; border-radius: 4px;">
                    <div style="height: 100%; width: ${accuracy}%; background: ${accuracy >= 80 ? '#10b981' : accuracy >= 60 ? '#38bdf8' : '#f59e0b'}; border-radius: 4px;"></div>
                </div>
            </div>
        `;
    }
}

function showLoading(message) {
    let loader = document.getElementById('chart-loading');
    if (!loader) {
        loader = document.createElement('div');
        loader.id = 'chart-loading';
        loader.style.cssText = `
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            background: rgba(30, 41, 59, 0.9);
            padding: 20px 40px;
            border-radius: 12px;
            display: flex;
            flex-direction: column;
            align-items: center;
            z-index: 100;
        `;
        document.querySelector('.chart-container').style.position = 'relative';
        document.querySelector('.chart-container').appendChild(loader);
    }
    
    loader.innerHTML = `
        <div style="width: 40px; height: 40px; border: 3px solid #38bdf8; border-top-color: transparent; border-radius: 50%; animation: spin 1s linear infinite;"></div>
        <p style="margin-top: 15px; color: #38bdf8;">${message}</p>
    `;
}

function hideLoading() {
    const loader = document.getElementById('chart-loading');
    if (loader) {
        loader.remove();
    }
}

// Export functionality
function exportChartData() {
    const data = cryptoChart.data;
    const csvContent = "data:text/csv;charset=utf-8," 
        + ["Date,Price"].concat(
            data.labels.map((label, i) => `${label},${data.datasets[0].data[i]}`)
        ).join("\n");
    
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", "crypto_history.csv");
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

// Add export button if not exists
if (!document.querySelector('.export-btn')) {
    const exportBtn = document.createElement('button');
    exportBtn.className = 'btn btn-secondary export-btn';
    exportBtn.innerHTML = '<i class="fas fa-download"></i> Export Data';
    exportBtn.onclick = exportChartData;
    exportBtn.style.marginLeft = '10px';
    
    const controls = document.querySelector('.chart-controls');
    if (controls) {
        controls.appendChild(exportBtn);
    }
}

// Add CSS for animations
const style = document.createElement('style');
style.textContent = `
    @keyframes spin {
        to { transform: rotate(360deg); }
    }
    
    .chart-container {
        position: relative;
        min-height: 400px;
    }
`;
document.head.appendChild(style);
let chart;

function loadHistory(coin = "bitcoin") {
    fetch(`/api/history/${coin}`)
        .then(res => res.json())
        .then(data => {
            const ctx = document.getElementById("cryptoChart").getContext("2d");

            if (chart) {
                chart.destroy();
            }

            chart = new Chart(ctx, {
                type: "line",
                data: {
                    labels: data.times,
                    datasets: [{
                        label: coin.toUpperCase() + " Price",
                        data: data.prices,
                        borderWidth: 2,
                        fill: false
                    }]
                }
            });
        })
        .catch(err => console.error("History error:", err));
}

// Default load
loadHistory("bitcoin");

// Called from buttons
function changeCoin(coin) {
    loadHistory(coin);
}
