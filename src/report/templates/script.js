// TEE-TA Vulnerability Analysis Report Scripts

// 対話履歴の折りたたみ機能
document.querySelectorAll('.conversation-header').forEach(header => {
    header.addEventListener('click', () => {
        const content = header.nextElementSibling;
        const icon = header.querySelector('.toggle-icon');
        content.classList.toggle('collapsed');
        icon.classList.toggle('collapsed');
    });
});

// 初期状態で2番目以降の対話履歴を折りたたむ
document.addEventListener('DOMContentLoaded', () => {
    // 対話履歴の初期状態設定
    document.querySelectorAll('.conversation-content').forEach((content, index) => {
        if (index > 0) { // 最初のものは開いたままにする
            content.classList.add('collapsed');
            const icon = content.previousElementSibling.querySelector('.toggle-icon');
            if (icon) icon.classList.add('collapsed');
        }
    });
    
    // 統計カードのアニメーション
    document.querySelectorAll('.stat-card').forEach((card, index) => {
        card.style.animationDelay = `${index * 0.1}s`;
        card.style.animation = 'fadeIn 0.5s ease forwards';
    });
    
    // スムーズスクロール
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });
    
    // コードブロックのコピー機能
    addCopyButtons();
});

// コードブロックにコピーボタンを追加
function addCopyButtons() {
    document.querySelectorAll('pre').forEach((block) => {
        // すでにボタンがある場合はスキップ
        if (block.querySelector('.copy-button')) return;
        
        // コピーボタンを作成
        const button = document.createElement('button');
        button.className = 'copy-button';
        button.textContent = 'Copy';
        button.style.cssText = `
            position: absolute;
            top: 8px;
            right: 8px;
            padding: 4px 8px;
            background: rgba(255,255,255,0.1);
            color: #fff;
            border: 1px solid rgba(255,255,255,0.2);
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
            transition: all 0.2s;
        `;
        
        // 親要素の位置を相対的に設定
        block.style.position = 'relative';
        
        // クリックイベント
        button.addEventListener('click', async () => {
            const text = block.textContent.replace('Copy', '').trim();
            try {
                await navigator.clipboard.writeText(text);
                button.textContent = 'Copied!';
                button.style.background = 'rgba(39, 174, 96, 0.3)';
                setTimeout(() => {
                    button.textContent = 'Copy';
                    button.style.background = 'rgba(255,255,255,0.1)';
                }, 2000);
            } catch (err) {
                console.error('Failed to copy:', err);
                button.textContent = 'Failed';
                setTimeout(() => {
                    button.textContent = 'Copy';
                }, 2000);
            }
        });
        
        // ホバー効果
        button.addEventListener('mouseenter', () => {
            button.style.background = 'rgba(255,255,255,0.2)';
        });
        
        button.addEventListener('mouseleave', () => {
            button.style.background = 'rgba(255,255,255,0.1)';
        });
        
        block.appendChild(button);
    });
}

// 検索機能
function addSearchFunctionality() {
    const searchInput = document.createElement('input');
    searchInput.type = 'text';
    searchInput.placeholder = 'Search in report...';
    searchInput.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 8px 12px;
        border: 1px solid var(--border-color);
        border-radius: 20px;
        width: 200px;
        z-index: 1000;
        background: white;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    `;
    
    document.body.appendChild(searchInput);
    
    let searchTimeout;
    searchInput.addEventListener('input', (e) => {
        clearTimeout(searchTimeout);
        searchTimeout = setTimeout(() => {
            performSearch(e.target.value);
        }, 300);
    });
}

// 検索実行
function performSearch(query) {
    // 既存のハイライトを削除
    document.querySelectorAll('.search-highlight').forEach(el => {
        el.classList.remove('search-highlight');
        el.style.backgroundColor = '';
    });
    
    if (!query) return;
    
    const searchRegex = new RegExp(query, 'gi');
    const textNodes = getTextNodes(document.body);
    
    textNodes.forEach(node => {
        if (searchRegex.test(node.textContent)) {
            const parent = node.parentElement;
            if (parent && !parent.classList.contains('search-highlight')) {
                parent.classList.add('search-highlight');
                parent.style.backgroundColor = 'yellow';
                parent.scrollIntoView({ behavior: 'smooth', block: 'center' });
            }
        }
    });
}

// テキストノードを取得
function getTextNodes(element) {
    const textNodes = [];
    const walker = document.createTreeWalker(
        element,
        NodeFilter.SHOW_TEXT,
        {
            acceptNode: function(node) {
                if (node.parentElement.tagName === 'SCRIPT' || 
                    node.parentElement.tagName === 'STYLE') {
                    return NodeFilter.FILTER_REJECT;
                }
                return NodeFilter.FILTER_ACCEPT;
            }
        }
    );
    
    let node;
    while (node = walker.nextNode()) {
        textNodes.push(node);
    }
    return textNodes;
}

// 印刷用の処理
window.addEventListener('beforeprint', () => {
    // すべての折りたたみを展開
    document.querySelectorAll('.conversation-content.collapsed').forEach(content => {
        content.classList.remove('collapsed');
    });
});

window.addEventListener('afterprint', () => {
    // 2番目以降を再度折りたたむ
    document.querySelectorAll('.conversation-content').forEach((content, index) => {
        if (index > 0) {
            content.classList.add('collapsed');
        }
    });
});