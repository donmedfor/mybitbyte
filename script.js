// ============================================================
// MyBitByte — script.js
// ============================================================

// ============================================================
// CONFIG: Map page IDs → Markdown file paths
// ============================================================

const pageFiles = {
    'home':       'writeups/home/home.md',
    'casino':     'writeups/casino/casino.md',
    'second':     'writeups/second/second.md',
    'mapper':     'writeups/mapper/mapper.md',
    'walnut':     'writeups/walnut/walnut.md',
    'aftermatch': 'writeups/aftermatch/aftermatch.md',
    'defense':    'writeups/defense/defense.md',
};

// ============================================================
// HARDCODED PAGES (Tools, About)
// ============================================================

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
            <span>Certipy</span>
            <span>Rubeus</span>
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
    `,
};

// ============================================================
// DOM REFS
// ============================================================

const main          = document.getElementById('mainContent');
const sidebar       = document.getElementById('sidebar');
const menuToggle    = document.getElementById('menuToggle');
const backdrop      = document.getElementById('sidebarBackdrop');
const themeToggle   = document.getElementById('themeToggle');
const searchInput   = document.getElementById('searchInput');
const navLinks      = document.querySelectorAll('.nav a[data-page]');

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

    // Reset scroll
    main.scrollTo({ top: 0, behavior: 'instant' });
    window.scrollTo({ top: 0, behavior: 'instant' });

    // Re-trigger page fade-in animation
    main.classList.remove('animate-fade-in');
    void main.offsetWidth; // force reflow
    main.classList.add('animate-fade-in');

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

    // Post-render enhancements
    enhanceCodeBlocks();
    addHeadingAnchors();
    wrapTables();
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

/**
 * Adds a copy-to-clipboard button to every <pre> block.
 */
function enhanceCodeBlocks() {
    main.querySelectorAll('pre').forEach(pre => {
        if (pre.querySelector('.copy-btn')) return;

        const btn = document.createElement('button');
        btn.className = 'copy-btn';
        btn.type = 'button';
        btn.setAttribute('aria-label', 'Copy code');
        btn.innerHTML = '<i class="fas fa-copy"></i>';

        btn.addEventListener('click', async () => {
            const code = pre.querySelector('code')?.innerText ?? pre.innerText;
            const done = () => {
                btn.innerHTML = '<i class="fas fa-check"></i>';
                btn.classList.add('copied');
                setTimeout(() => {
                    btn.innerHTML = '<i class="fas fa-copy"></i>';
                    btn.classList.remove('copied');
                }, 1500);
            };

            try {
                await navigator.clipboard.writeText(code);
                done();
            } catch {
                // Fallback for insecure contexts
                const ta = document.createElement('textarea');
                ta.value = code;
                ta.style.position = 'fixed';
                ta.style.opacity = '0';
                document.body.appendChild(ta);
                ta.select();
                try { document.execCommand('copy'); } catch {}
                document.body.removeChild(ta);
                done();
            }
        });

        pre.appendChild(btn);
    });
}

/**
 * Adds slug IDs to h2/h3 for anchor linking.
 */
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

/**
 * Wraps tables in a scroll container for narrow viewports.
 */
function wrapTables() {
    main.querySelectorAll('table').forEach(table => {
        if (table.parentElement.classList.contains('table-wrap')) return;
        const wrapper = document.createElement('div');
        wrapper.className = 'table-wrap';
        table.parentNode.insertBefore(wrapper, table);
        wrapper.appendChild(table);
    });
}

// ============================================================
// SEARCH
// ============================================================

if (searchInput) {
    searchInput.addEventListener('input', function () {
        const query = this.value.toLowerCase().trim();
        const links = document.querySelectorAll('.nav a[data-page]');

        // Filter individual links
        links.forEach(link => {
            const text = link.textContent.toLowerCase();
            const parent = link.closest('li');
            if (!parent) return;
            parent.style.display = (text.includes(query) || query === '') ? '' : 'none';
        });

        // Hide section titles whose children are all hidden
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
        const page = link.dataset.page;
        if (!page) return;
        renderPage(page);
        closeSidebar();
    });
});

// ============================================================
// MOBILE TOGGLE + BACKDROP
// ============================================================

if (menuToggle) {
    menuToggle.addEventListener('click', (e) => {
        e.stopPropagation();
        const isOpen = sidebar.classList.toggle('open');
        if (backdrop) backdrop.classList.toggle('show', isOpen);
        menuToggle.innerHTML = isOpen
            ? '<i class="fas fa-xmark text-sm"></i>'
            : '<i class="fas fa-bars text-sm"></i>';
    });
}

if (backdrop) {
    backdrop.addEventListener('click', () => {
        closeSidebar();
        menuToggle.innerHTML = '<i class="fas fa-bars text-sm"></i>';
    });
}

// Outside-click close (mobile)
document.addEventListener('click', (e) => {
    if (window.innerWidth > 768) return;
    if (!sidebar.contains(e.target) && e.target !== menuToggle && !menuToggle.contains(e.target)) {
        closeSidebar();
        menuToggle.innerHTML = '<i class="fas fa-bars text-sm"></i>';
    }
});

// Escape key closes sidebar
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        closeSidebar();
        if (menuToggle) menuToggle.innerHTML = '<i class="fas fa-bars text-sm"></i>';
    }
});

// ============================================================
// THEME TOGGLE
// ============================================================

function updateThemeIcon() {
    if (!themeToggle) return;
    const icon = themeToggle.querySelector('i');
    if (!icon) return;
    const isLight = document.body.classList.contains('light');
    icon.className = isLight ? 'fas fa-sun text-sm' : 'fas fa-moon text-sm';
    // Update meta theme-color for mobile chrome
    const meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.content = isLight ? '#ffffff' : '#0a0a0b';
}

// Restore saved theme on load
(function initTheme() {
    const saved = localStorage.getItem('theme');
    if (saved === 'light') {
        document.body.classList.add('light');
    }
    updateThemeIcon();
})();

if (themeToggle) {
    themeToggle.addEventListener('click', () => {
        document.body.classList.toggle('light');
        const isLight = document.body.classList.contains('light');
        localStorage.setItem('theme', isLight ? 'light' : 'dark');
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

document.addEventListener('keydown', (e) => {
    // "/" focuses search (unless typing in a field)
    if (
        e.key === '/' &&
        document.activeElement !== searchInput &&
        !['INPUT', 'TEXTAREA'].includes(document.activeElement.tagName)
    ) {
        e.preventDefault();
        searchInput?.focus();
    }
});

// ============================================================
// INIT: handle resize — collapse mobile menu when going wide
// ============================================================

window.addEventListener('resize', () => {
    if (window.innerWidth > 768) {
        sidebar.classList.remove('open');
        if (backdrop) backdrop.classList.remove('show');
        if (menuToggle) menuToggle.innerHTML = '<i class="fas fa-bars text-sm"></i>';
    }
});
