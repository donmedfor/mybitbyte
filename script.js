// ============================================================
// CONFIG: Map page IDs to Markdown files
// ============================================================

const pageFiles = {
    'home': 'writeups/home/home.md',
    'casino': 'writeups/casino/casino.md',
    'second': 'writeups/second/second.md',
};

// ── Hardcoded pages (Tools, About) ──
const hardcodedPages = {
    tools: `
    <h1>Security Tools</h1>
    <ul>
        <li><strong>Nmap</strong> – Network scanning</li>
        <li><strong>Burp Suite</strong> – Web proxy & testing</li>
        <li><strong>Metasploit</strong> – Exploitation framework</li>
        <li><strong>Gobuster</strong> – Directory busting</li>
        <li><strong>John the Ripper</strong> – Password cracking</li>
        <li><strong>Wireshark</strong> – Packet analysis</li>
        <li><strong>BloodHound</strong> – AD enumeration</li>
        <li><strong>Impacket</strong> – Network protocols</li>
    </ul>
    <p><a href="#" data-page="home">← Back to Home</a></p>
    `,

    about: `
    <h1>About</h1>
    <p>Hi, I'm a cybersecurity engineer with a passion for penetration testing and red teaming. I hold a master's degree in computer science and am currently pursuing the OSCP certification.</p>
    <p>This site is a collection of my writeups from various CTF platforms. My goal is to share knowledge and help others learn.</p>
    <p>Connect with me:</p>
    <ul>
        <li><a href="https://github.com/donmedfor" target="_blank">GitHub</a></li>
        <li><a href="https://twitter.com/yourhandle" target="_blank">Twitter</a></li>
    </ul>
    <p><a href="#" data-page="home">← Back to Home</a></p>
    `
};

// ============================================================
// RENDER ENGINE
// ============================================================

const main = document.getElementById('mainContent');
const navLinks = document.querySelectorAll('.nav a[data-page]');
const searchInput = document.getElementById('searchInput');
const sidebar = document.getElementById('sidebar');
const menuToggle = document.getElementById('menuToggle');

async function renderPage(pageId) {
    let htmlContent = '';

    // 1. Check if it's a hardcoded page
    if (hardcodedPages[pageId]) {
        htmlContent = hardcodedPages[pageId];
    }
    // 2. Check if it's a Markdown file
    else if (pageFiles[pageId]) {
        try {
            const response = await fetch(pageFiles[pageId]);
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            const markdown = await response.text();
            htmlContent = marked.parse(markdown);
        } catch (error) {
            htmlContent = `
                <h1>Writeup Not Found</h1>
                <p>Could not load <code>${pageFiles[pageId]}</code>.</p>
                <p>Make sure the file exists in the <code>writeups/</code> folder.</p>
                <p><a href="#" data-page="home">← Back to Home</a></p>
            `;
        }
    }
    // 3. Not found
    else {
        htmlContent = `<h1>404</h1><p>Page not found.</p><p><a href="#" data-page="home">← Back to Home</a></p>`;
    }

    main.innerHTML = htmlContent;

    // Highlight active link
    navLinks.forEach(link => link.classList.remove('active'));
    const activeLink = document.querySelector(`.nav a[data-page="${pageId}"]`);
    if (activeLink) activeLink.classList.add('active');

    // Update URL hash
    if (history.pushState) {
        history.pushState(null, '', `#${pageId}`);
    }

    // Close mobile sidebar
    if (window.innerWidth <= 768) {
        sidebar.classList.remove('open');
    }

    // Re-bind internal links (for navigation within rendered content)
    main.querySelectorAll('a[data-page]').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            renderPage(link.dataset.page);
        });
    });
}

// ─── SEARCH ───
searchInput.addEventListener('input', function() {
    const query = this.value.toLowerCase().trim();
    const links = document.querySelectorAll('.nav a[data-page]');
    links.forEach(link => {
        const text = link.textContent.toLowerCase();
        const parent = link.closest('li');
        if (text.includes(query) || query === '') {
            parent.style.display = '';
        } else {
            parent.style.display = 'none';
        }
    });
});

// ─── NAVIGATION ───
navLinks.forEach(link => {
    link.addEventListener('click', (e) => {
        e.preventDefault();
        renderPage(link.dataset.page);
    });
});

// ─── MOBILE TOGGLE ───
menuToggle.addEventListener('click', () => {
    sidebar.classList.toggle('open');
});

// ─── THEME TOGGLE ───
const themeToggle = document.getElementById('themeToggle');
themeToggle.addEventListener('click', () => {
    document.body.classList.toggle('light');
    const icon = themeToggle.querySelector('i');
    icon.className = document.body.classList.contains('light') ? 'fas fa-sun' : 'fas fa-moon';
});

// ─── LOAD FROM HASH ───
function loadFromHash() {
    const hash = window.location.hash.replace('#', '');
    const page = hash && (hardcodedPages[hash] || pageFiles[hash]) ? hash : 'home';
    renderPage(page);
}

window.addEventListener('hashchange', loadFromHash);
loadFromHash();

// ─── CLOSE SIDEBAR ON OUTSIDE CLICK ───
document.addEventListener('click', (e) => {
    if (window.innerWidth <= 768) {
        if (!sidebar.contains(e.target) && e.target !== menuToggle) {
            sidebar.classList.remove('open');
        }
    }
});

console.log('🟢 MyBitByte – Writeups loaded.');
