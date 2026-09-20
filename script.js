// ============================================================
// CONFIG: Map page IDs to Markdown files
// ============================================================

const pageFiles = {
    'home': 'writeups/home/home.md',
    'casino': 'writeups/casino/casino.md',
    'second': 'writeups/second/second.md',
    'mapper': 'writeups/mapper/mapper.md',
    'walnut': 'writeups/walnut/walnut.md',
    'aftermatch': 'writeups/aftermatch/aftermatch.md',
    'defense': 'writeups/defense/defense.md',
};

// ── Hardcoded pages (Tools, About) ──
const hardcodedPages = {
    tools: `
    <h1>Security Tools</h1>
    <p>The toolkit I reach for most often during engagements and CTFs.</p>
    <div class="tool-grid">
        <span>Nmap</span>
        <span>Burp Suite</span>
        <span>Metasploit</span>
        <span>Gobuster</span>
        <span>ffuf</span>
        <span>John the Ripper</span>
        <span>Hashcat</span>
        <span>Wireshark</span>
        <span>BloodHound</span>
        <span>Impacket</span>
        <span>NetExec</span>
        <span>Responder</span>
        <span>evil-winrm</span>
        <span>BloodyAD</span>
    </div>
    <p><a href="#" data-page="home">← Back to Home</a></p>
    `,

    about: `
    <h1>About</h1>
    <p>Hi, I'm a cybersecurity engineer with a passion for penetration testing and red teaming. I hold a master's degree in computer science and am currently pursuing the OSCP certification.</p>
    <p>This site is a collection of my writeups from various CTF platforms. My goal is to share knowledge and help others learn.</p>
    <h2>Connect</h2>
    <ul>
        <li><a href="https://github.com/donmedfor" target="_blank" rel="noopener">GitHub</a></li>
        <li><a href="https://twitter.com/yourhandle" target="_blank" rel="noopener">Twitter</a></li>
    </ul>
    <p><a href="#" data-page="home">← Back to Home</a></p>
    `
};

// ============================================================
// DOM REFS
// ============================================================

const main = document.getElementById('mainContent');
const navLinks = document.querySelectorAll('.nav a[data-page]');
const searchInput = document.getElementById('searchInput');
const sidebar = document.getElementById('sidebar');
const menuToggle = document.getElementById('menuToggle');
const backdrop = document.getElementById('sidebarBackdrop');
const themeToggle = document.getElementById('themeToggle');

// ============================================================
// RENDER ENGINE
// ============================================================

async function renderPage(pageId) {
    let htmlContent = '';

    // 1. Hardcoded page
    if (hardcodedPages[pageId]) {
        htmlContent = hardcodedPages[pageId];
    }
    // 2. Markdown file
    else if (pageFiles[pageId]) {
        try {
            const response = await fetch(pageFiles[pageId]);
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
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
    // 3. 404
    else {
        htmlContent = `
            <h1>404</h1>
            <p>Page not found.</p>
            <p><a href="#" data-page="home">← Back to Home</a></p>
        `;
    }

    main.innerHTML = htmlContent;

    // Scroll to top on navigation
    main.scrollTo({ top: 0, behavior: 'instant' });
    window.scrollTo({ top: 0, behavior: 'instant' });

    // Highlight active nav link
    navLinks.forEach(link => link.classList.remove('active'));
    const activeLink = document.querySelector(`.nav a[data-page="${pageId}"]`);
    if (activeLink) activeLink.classList.add('active');

    // Update URL hash
    if (history.pushState) {
        history.pushState(null, '', `#${pageId}`);
    }

    // Close mobile sidebar
    closeSidebar();

    // Re-bind internal links inside rendered content
    main.querySelectorAll('a[data-page]').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            renderPage(link.dataset.page);
        });
    });

    // Add copy buttons to code blocks
    enhanceCodeBlocks();

    // Add IDs to headings for anchor links
    addHeadingAnchors();
}

// ============================================================
// HELPERS
// ============================================================

function closeSidebar() {
    if (window.innerWidth <= 768) {
        sidebar.classList.remove('open');
        if (backdrop) backdrop.classList.remove('show');
    }
}

function enhanceCodeBlocks() {
    main.querySelectorAll('pre').forEach(pre => {
        // Skip if already enhanced
        if (pre.querySelector('.copy-btn')) return;

        const btn = document.createElement('button');
        btn.className = 'copy-btn';
        btn.type = 'button';
        btn.setAttribute('aria-label', 'Copy code');
        btn.innerHTML = '<i class="fas fa-copy"></i>';

        btn.addEventListener('click', async () => {
            const code = pre.querySelector('code')?.innerText ?? pre.innerText;
            try {
                await navigator.clipboard.writeText(code);
                btn.innerHTML = '<i class="fas fa-check"></i>';
                btn.classList.add('copied');
                setTimeout(() => {
                    btn.innerHTML = '<i class="fas fa-copy"></i>';
                    btn.classList.remove('copied');
                }, 1500);
            } catch {
                // Fallback for older browsers / non-secure contexts
                const ta = document.createElement('textarea');
                ta.value = code;
                document.body.appendChild(ta);
                ta.select();
                try { document.execCommand('copy'); } catch {}
                document.body.removeChild(ta);
                btn.innerHTML = '<i class="fas fa-check"></i>';
                setTimeout(() => { btn.innerHTML = '<i class="fas fa-copy"></i>'; }, 1500);
            }
        });

        pre.appendChild(btn);
    });
}

function addHeadingAnchors() {
    main.querySelectorAll('h2, h3').forEach(heading => {
        if (heading.id) return;
        const slug = heading.textContent
            .toLowerCase()
            .trim()
            .replace(/[^\w\s-]/g, '')
            .replace(/\s+/g, '-')
            .replace(/-+/g, '-')
            .slice(0, 60);
        heading.id = slug || `h-${Math.random().toString(36).slice(2, 8)}`;
    });
}

// ============================================================
// SEARCH
// ============================================================

if (searchInput) {
    searchInput.addEventListener('input', function () {
        const query = this.value.toLowerCase().trim();
        const links = document.querySelectorAll('.nav a[data-page]');

        links.forEach(link => {
            const text = link.textContent.toLowerCase();
            const parent = link.closest('li');
            if (!parent) return;
            parent.style.display = (text.includes(query) || query === '') ? '' : 'none';
        });

        // Also filter the section titles — hide if all children hidden
        document.querySelectorAll('.nav .section-title').forEach(title => {
            let next = title.nextElementSibling;
            let anyVisible = false;
            while (next && !next.classList.contains('section-title')) {
                if (next.style.display !== 'none') { anyVisible = true; break; }
                next = next.nextElementSibling;
            }
            title.style.display = (anyVisible || query === '') ? '' : 'none';
        });
    });
}

// ============================================================
// NAVIGATION
// ============================================================

navLinks.forEach(link => {
    link.addEventListener('click', (e) => {
        e.preventDefault();
        renderPage(link.dataset.page);
        closeSidebar();
    });
});

// ============================================================
// MOBILE TOGGLE + BACKDROP
// ============================================================

if (menuToggle) {
    menuToggle.addEventListener('click', (e) => {
        e.stopPropagation();
        sidebar.classList.toggle('open');
        if (backdrop) backdrop.classList.toggle('show', sidebar.classList.contains('open'));
    });
}

if (backdrop) {
    backdrop.addEventListener('click', closeSidebar);
}

// Close sidebar on outside click (mobile)
document.addEventListener('click', (e) => {
    if (window.innerWidth > 768) return;
    if (!sidebar.contains(e.target) && e.target !== menuToggle && !menuToggle.contains(e.target)) {
        closeSidebar();
    }
});

// Close on Escape
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeSidebar();
});

// ============================================================
// THEME TOGGLE
// ============================================================

// Restore saved theme on load
(function initTheme() {
    const saved = localStorage.getItem('theme');
    if (saved === 'light') {
        document.body.classList.add('light');
        updateThemeIcon();
    }
})();

function updateThemeIcon() {
    if (!themeToggle) return;
    const icon = themeToggle.querySelector('i');
    if (!icon) return;
    icon.className = document.body.classList.contains('light')
        ? 'fas fa-sun'
        : 'fas fa-moon';
}

if (themeToggle) {
    themeToggle.addEventListener('click', () => {
        document.body.classList.toggle('light');
        localStorage.setItem(
            'theme',
            document.body.classList.contains('light') ? 'light' : 'dark'
        );
        updateThemeIcon();
    });
}

// ============================================================
// HASH ROUTING
// ============================================================

function loadFromHash() {
    const hash = window.location.hash.replace('#', '');
    const page = hash && (hardcodedPages[hash] || pageFiles[hash]) ? hash : 'home';
    renderPage(page);
}

window.addEventListener('hashchange', loadFromHash);

// Initial load
loadFromHash();

// ============================================================
// KEYBOARD SHORTCUTS
// ============================================================

// "/" focuses search
document.addEventListener('keydown', (e) => {
    if (e.key === '/' && document.activeElement !== searchInput) {
        e.preventDefault();
        searchInput?.focus();
    }
});
