// Brand Sentinel Dashboard - Main JavaScript

document.addEventListener('DOMContentLoaded', () => {
    console.log('Brand Sentinel Dashboard loaded');

    // Add active class to current nav link
    const currentPath = window.location.pathname;
    document.querySelectorAll('.nav-link').forEach(link => {
        if (link.getAttribute('href') === currentPath) {
            link.classList.add('active');
        }
    });
});

// Utility functions
function formatNumber(num) {
    return new Intl.NumberFormat('es-MX').format(num);
}

function formatDate(dateStr) {
    const date = new Date(dateStr);
    return date.toLocaleDateString('es-MX', {
        year: 'numeric',
        month: 'short',
        day: 'numeric'
    });
}

// Auto-refresh stats every 30 seconds on dashboard
if (window.location.pathname === '/') {
    setInterval(async () => {
        try {
            const resp = await fetch('/api/stats');
            const stats = await resp.json();
            // Update stat values if they exist
            document.querySelectorAll('[data-stat]').forEach(el => {
                const key = el.dataset.stat;
                if (stats[key] !== undefined) {
                    el.textContent = formatNumber(stats[key]);
                }
            });
        } catch (err) {
            console.error('Failed to refresh stats:', err);
        }
    }, 30000);
}
