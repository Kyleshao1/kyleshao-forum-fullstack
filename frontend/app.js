// Configuration
const API_BASE_URL = 'https://kyleshao-forum-backend.onrender.com';

// State management
let currentUser = null;
let authToken = null;
let posts = [];
let conversations = [];
let currentConversation = null;

// DOM Elements
const sections = {
    home: document.getElementById('home-section'),
    posts: document.getElementById('posts-section'),
    create: document.getElementById('create-section'),
    profile: document.getElementById('profile-section'),
    messages: document.getElementById('messages-section'),
    tickets: document.getElementById('tickets-section')
};

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    console.log('Forum app initialized');
    checkAuth();
    setupEventListeners();
    
    // 默认显示home部分
    if (sections.home) {
        showSection('home');
    } else {
        console.error('Home section not found');
    }
});

// Auth Functions
function toggleAuth() {
    const modal = document.getElementById('auth-modal');
    if (modal) {
        modal.classList.toggle('hidden');
    }
}

function toggleAuthType() {
    const title = document.getElementById('auth-title');
    const toggle = document.getElementById('auth-toggle');
    const emailInput = document.getElementById('auth-email');
    const confirmInput = document.getElementById('auth-confirm-password');
    
    if (!title) return;
    
    if (title.textContent === 'Login') {
        title.textContent = 'Register';
        if (toggle) toggle.innerHTML = 'Already have an account? <a href="#" onclick="toggleAuthType()">Login</a>';
        if (emailInput) emailInput.classList.remove('hidden');
        if (confirmInput) confirmInput.classList.remove('hidden');
    } else {
        title.textContent = 'Login';
        if (toggle) toggle.innerHTML = 'Don\'t have an account? <a href="#" onclick="toggleAuthType()">Register</a>';
        if (emailInput) emailInput.classList.add('hidden');
        if (confirmInput) confirmInput.classList.add('hidden');
    }
}

async function handleAuth() {
    const username = document.getElementById('auth-username')?.value;
    const email = document.getElementById('auth-email')?.value;
    const password = document.getElementById('auth-password')?.value;
    const confirm = document.getElementById('auth-confirm-password')?.value;
    const isRegister = document.getElementById('auth-title')?.textContent === 'Register';
    
    if (!username || !password) {
        alert('Username and password are required');
        return;
    }
    
    if (isRegister) {
        if (!email) {
            alert('Email is required for registration');
            return;
        }
        if (password !== confirm) {
            alert('Passwords do not match');
            return;
        }
        await register(username, email, password);
    } else {
        await login(username, password);
    }
}

async function login(username, password) {
    try {
        const response = await fetch(`${API_BASE_URL}/api/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        
        if (response.ok) {
            const data = await response.json();
            authToken = data.token;
            currentUser = data.user;
            localStorage.setItem('token', authToken);
            localStorage.setItem('user', JSON.stringify(currentUser));
            
            updateUI();
            toggleAuth();
            showSection('home');
            
            // 加载帖子
            loadPosts();
            
            if (currentUser.role === 'admin' || currentUser.role === 'super_admin') {
                const adminPanel = document.getElementById('admin-panel');
                if (adminPanel) adminPanel.classList.remove('hidden');
            }
        } else {
            const error = await response.json().catch(() => ({ error: 'Login failed' }));
            alert(error.error || 'Login failed');
        }
    } catch (error) {
        console.error('Login error:', error);
        alert('Login failed. Please check your connection.');
    }
}

async function register(username, email, password) {
    try {
        const response = await fetch(`${API_BASE_URL}/api/auth/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, email, password })
        });
        
        if (response.ok) {
            const result = await response.json();
            alert('Registration successful! Please login.');
            toggleAuthType();
        } else {
            const error = await response.json().catch(() => ({ error: 'Registration failed' }));
            alert(error.error || 'Registration failed');
        }
    } catch (error) {
        console.error('Register error:', error);
        alert('Registration failed. Please check your connection.');
    }
}

function logout() {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    authToken = null;
    currentUser = null;
    updateUI();
    showSection('home');
    loadPosts(); // 重新加载帖子（作为游客）
}

function checkAuth() {
    const token = localStorage.getItem('token');
    const user = localStorage.getItem('user');
    
    if (token && user) {
        try {
            authToken = token;
            currentUser = JSON.parse(user);
            updateUI();
        } catch (e) {
            console.error('Error parsing user data:', e);
        }
    }
}

function updateUI() {
    const authLink = document.getElementById('auth-link');
    if (!authLink) return;
    
    if (currentUser) {
        authLink.textContent = 'Logout';
        authLink.onclick = logout;
        const profileUsername = document.getElementById('profile-username');
        if (profileUsername) profileUsername.textContent = currentUser.username;
    } else {
        authLink.textContent = 'Login';
        authLink.onclick = toggleAuth;
    }
}

// Navigation
function showSection(sectionName) {
    if (!sections[sectionName]) {
        console.error(`Section ${sectionName} not found`);
        return;
    }
    
    // 先隐藏所有section
    Object.entries(sections).forEach(([name, section]) => {
        if (section) {
            if (name === sectionName) {
                section.classList.remove('hidden');
            } else {
                section.classList.add('hidden');
            }
        }
    });
    
    if (sectionName === 'profile' && currentUser) {
        loadProfile();
    } else if (sectionName === 'posts') {
        loadPosts();
    } else if (sectionName === 'messages' && currentUser) {
        loadConversations();
    }
}

// Post Functions
async function loadPosts() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/posts`);
        if (response.ok) {
            const data = await response.json();
            // 确保data是数组
            if (Array.isArray(data)) {
                posts = data;
                renderPosts();
            } else {
                console.error('API did not return an array:', data);
                posts = [];
                renderPosts();
            }
        } else {
            console.error('Failed to load posts:', response.status);
            posts = [];
            renderPosts();
        }
    } catch (error) {
        console.error('Error loading posts:', error);
        posts = [];
        renderPosts();
    }
}

function renderPosts() {
    const container = document.getElementById('posts-container');
    if (!container) return;
    
    if (!posts || posts.length === 0) {
        container.innerHTML = '<p>No posts yet. Be the first to post!</p>';
        return;
    }
    
    container.innerHTML = posts.map(post => {
        // 检查post是否有必要的字段
        if (!post || !post.id) return '';
        
        const username = post.username || 'Anonymous';
        const vitality = post.vitality || 0;
        const role = post.role || 'user';
        const likes_count = post.likes_count || 0;
        const useful_count = post.useful_count || 0;
        const replies_count = post.replies_count || 0;
        
        return `
        <div class="post" data-id="${post.id}">
            <div class="post-header">
                <div class="post-author">
                    <span class="username">${username}</span>
                    <span class="badge ${getBadgeClass(vitality, role)}">
                        ${getBadgeName(vitality, role)}
                    </span>
                </div>
                <span class="post-date">${new Date(post.created_at).toLocaleDateString()}</span>
            </div>
            <h3 class="post-title">${post.title || 'Untitled'}</h3>
            <div class="post-content">${renderMarkdown(post.content || '')}</div>
            <div class="post-actions">
                ${currentUser ? `
                    <button class="action-button" onclick="likePost(${post.id})">
                        <i class="fas fa-thumbs-up"></i>
                        <span>${likes_count}</span>
                    </button>
                    <button class="action-button" onclick="markUseful(${post.id})">
                        <i class="fas fa-check-circle"></i>
                        <span>${useful_count}</span>
                    </button>
                ` : `
                    <button class="action-button" onclick="toggleAuth()">
                        <i class="fas fa-thumbs-up"></i>
                        <span>${likes_count}</span>
                    </button>
                    <button class="action-button" onclick="toggleAuth()">
                        <i class="fas fa-check-circle"></i>
                        <span>${useful_count}</span>
                    </button>
                `}
                <button class="action-button" onclick="showReplies(${post.id})">
                    <i class="fas fa-comment"></i>
                    <span>${replies_count}</span>
                </button>
                ${currentUser && (currentUser.role === 'admin' || currentUser.role === 'super_admin') ? `
                    <button class="action-button danger" onclick="deletePost(${post.id})">
                        <i class="fas fa-trash"></i>
                    </button>
                ` : ''}
            </div>
            <div id="replies-${post.id}" class="replies-container hidden"></div>
        </div>
        `;
    }).join('');
}

async function createPost() {
    if (!currentUser) {
        alert('Please login to create a post');
        return;
    }
    
    const title = document.getElementById('post-title')?.value;
    const content = document.getElementById('post-content')?.value;
    
    if (!title || !content) {
        alert('Title and content are required');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE_URL}/api/posts`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            },
            body: JSON.stringify({ title, content })
        });
        
        if (response.ok) {
            alert('Post created successfully!');
            document.getElementById('post-title').value = '';
            document.getElementById('post-content').value = '';
            loadPosts();
            showSection('posts');
        } else {
            const error = await response.json().catch(() => ({ error: 'Failed to create post' }));
            alert(error.error || 'Failed to create post');
        }
    } catch (error) {
        console.error('Error creating post:', error);
        alert('Failed to create post. Please check your connection.');
    }
}

// Markdown and LaTeX Rendering
function renderMarkdown(text) {
    if (!text) return '';
    try {
        const html = marked.parse(text);
        return html.replace(/\$\$(.*?)\$\$/g, (match, latex) => {
            try {
                return katex.renderToString(latex, { throwOnError: false });
            } catch (e) {
                return match;
            }
        });
    } catch (e) {
        console.error('Error rendering markdown:', e);
        return text;
    }
}

function formatText(type) {
    const textarea = document.getElementById('post-content');
    if (!textarea) return;
    
    const start = textarea.selectionStart;
    const end = textarea.selectionEnd;
    const selectedText = textarea.value.substring(start, end);
    
    let formattedText = '';
    switch(type) {
        case 'bold':
            formattedText = `**${selectedText}**`;
            break;
        case 'italic':
            formattedText = `*${selectedText}*`;
            break;
        case 'code':
            formattedText = `\`${selectedText}\``;
            break;
    }
    
    textarea.value = textarea.value.substring(0, start) + 
                     formattedText + 
                     textarea.value.substring(end);
    textarea.focus();
}

function insertLatex() {
    const textarea = document.getElementById('post-content');
    if (!textarea) return;
    
    const latex = prompt('Enter LaTeX formula:');
    if (latex) {
        const cursorPos = textarea.selectionStart;
        textarea.value = textarea.value.substring(0, cursorPos) + 
                        `$${latex}$` + 
                        textarea.value.substring(cursorPos);
    }
}

// Profile Functions
async function loadProfile() {
    if (!currentUser) return;
    
    try {
        const response = await fetch(`${API_BASE_URL}/api/users/${currentUser.id}`, {
            headers: { 'Authorization': `Bearer ${authToken}` }
        });
        
        if (response.ok) {
            const userData = await response.json();
            
            document.getElementById('profile-vitality').textContent = userData.vitality || 0;
            document.getElementById('profile-bio').value = userData.bio || '';
            document.getElementById('profile-signature').value = userData.signature || '';
            
            const badge = document.getElementById('profile-badge');
            if (badge) {
                badge.className = `badge ${getBadgeClass(userData.vitality, userData.role)}`;
                badge.textContent = getBadgeName(userData.vitality, userData.role);
            }
        }
    } catch (error) {
        console.error('Error loading profile:', error);
    }
}

async function updateProfile() {
    const bio = document.getElementById('profile-bio')?.value || '';
    const signature = document.getElementById('profile-signature')?.value || '';
    
    try {
        const response = await fetch(`${API_BASE_URL}/api/users/${currentUser.id}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            },
            body: JSON.stringify({ bio, signature })
        });
        
        if (response.ok) {
            alert('Profile updated!');
        } else {
            alert('Failed to update profile');
        }
    } catch (error) {
        console.error('Error updating profile:', error);
        alert('Failed to update profile');
    }
}

// Message Functions
async function loadConversations() {
    if (!currentUser) return;
    
    try {
        const response = await fetch(`${API_BASE_URL}/api/messages/conversations`, {
            headers: { 'Authorization': `Bearer ${authToken}` }
        });
        
        if (response.ok) {
            const data = await response.json();
            if (Array.isArray(data)) {
                conversations = data;
                renderConversations();
            }
        }
    } catch (error) {
        console.error('Error loading conversations:', error);
    }
}

function renderConversations() {
    const container = document.getElementById('conversations-list');
    if (!container) return;
    
    if (!conversations || conversations.length === 0) {
        container.innerHTML = '<p>No conversations yet</p>';
        return;
    }
    
    container.innerHTML = conversations.map(conv => `
        <div class="conversation-item" onclick="loadConversation(${conv.user_id})">
            <div class="conv-user">${conv.username}</div>
            <div class="conv-preview">${(conv.last_message || '').substring(0, 50)}</div>
        </div>
    `).join('');
}

async function loadConversation(userId) {
    try {
        const response = await fetch(`${API_BASE_URL}/api/messages/${userId}`, {
            headers: { 'Authorization': `Bearer ${authToken}` }
        });
        
        if (response.ok) {
            const messages = await response.json();
            if (Array.isArray(messages)) {
                renderMessages(messages);
                currentConversation = userId;
            }
        }
    } catch (error) {
        console.error('Error loading conversation:', error);
    }
}

async function createTicket() {
    if (!currentUser) {
        alert('Please login to create a ticket');
        return;
    }
    
    const title = document.getElementById('ticket-title')?.value;
    const content = document.getElementById('ticket-content')?.value;
    
    if (!title || !content) {
        alert('Title and content are required');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE_URL}/api/tickets`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            },
            body: JSON.stringify({ title, content })
        });
        
        if (response.ok) {
            alert('Ticket created successfully!');
            document.getElementById('ticket-title').value = '';
            document.getElementById('ticket-content').value = '';
            loadUserTickets();
        } else {
            const error = await response.json().catch(() => ({ error: 'Failed to create ticket' }));
            alert(error.error || 'Failed to create ticket');
        }
    } catch (error) {
        console.error('Error creating ticket:', error);
        alert('Failed to create ticket. Please check your connection.');
    }
}

async function loadUserTickets() {
    if (!currentUser) return;
    
    try {
        const response = await fetch(`${API_BASE_URL}/api/tickets/user`, {
            headers: { 'Authorization': `Bearer ${authToken}` }
        });
        
        if (response.ok) {
            const tickets = await response.json();
            if (Array.isArray(tickets)) {
                renderTickets(tickets);
            }
        }
    } catch (error) {
        console.error('Error loading tickets:', error);
    }
}

function renderTickets(tickets) {
    const container = document.getElementById('tickets-container');
    if (!container) return;
    
    if (!tickets || tickets.length === 0) {
        container.innerHTML = '<p>No tickets yet.</p>';
        return;
    }
    
    container.innerHTML = tickets.map(ticket => `
        <div class="ticket" data-id="${ticket.id}">
            <div class="ticket-header">
                <h4>${ticket.title}</h4>
                <span class="ticket-status ${ticket.status}">${ticket.status}</span>
            </div>
            <div class="ticket-content">${ticket.content}</div>
            <div class="ticket-footer">
                <span class="ticket-date">Created: ${new Date(ticket.created_at).toLocaleString()}</span>
                ${currentUser && (currentUser.role === 'admin' || currentUser.role === 'super_admin') ? `
                    <div class="ticket-actions">
                        <button onclick="updateTicketStatus(${ticket.id}, 'pending')">Pending</button>
                        <button onclick="updateTicketStatus(${ticket.id}, 'completed')">Complete</button>
                        <button onclick="updateTicketStatus(${ticket.id}, 'closed')">Close</button>
                        <button class="danger" onclick="deleteTicket(${ticket.id})">Delete</button>
                    </div>
                ` : ''}
            </div>
        </div>
    `).join('');
}

// 更新导航函数，添加工单加载
function showSection(sectionName) {
    if (!sections[sectionName]) {
        console.error(`Section ${sectionName} not found`);
        return;
    }
    
    // 先隐藏所有section
    Object.entries(sections).forEach(([name, section]) => {
        if (section) {
            if (name === sectionName) {
                section.classList.remove('hidden');
            } else {
                section.classList.add('hidden');
            }
        }
    });
    
    if (sectionName === 'profile' && currentUser) {
        loadProfile();
    } else if (sectionName === 'posts') {
        loadPosts();
    } else if (sectionName === 'messages' && currentUser) {
        loadConversations();
    } else if (sectionName === 'tickets' && currentUser) {
        loadUserTickets();
        
        // 如果是管理员，显示管理面板并加载所有工单
        if (currentUser.role === 'admin' || currentUser.role === 'super_admin') {
            document.getElementById('admin-tickets-panel').classList.remove('hidden');
            loadAllTickets();
        } else {
            document.getElementById('admin-tickets-panel').classList.add('hidden');
        }
    }
}


function renderMessages(messages) {
    const container = document.getElementById('chat-messages');
    if (!container) return;
    
    if (!messages || messages.length === 0) {
        container.innerHTML = '<p>No messages yet</p>';
        return;
    }
    
    container.innerHTML = messages.map(msg => `
        <div class="message ${msg.sender_id === currentUser.id ? 'sent' : 'received'}">
            <div class="message-content">${msg.content || ''}</div>
            <div class="message-time">${new Date(msg.created_at).toLocaleTimeString()}</div>
        </div>
    `).join('');
    container.scrollTop = container.scrollHeight;
}

async function sendMessage() {
    if (!currentConversation) {
        alert('Please select a conversation first');
        return;
    }
    
    const input = document.getElementById('message-input');
    const content = input?.value.trim();
    
    if (!content) return;
    
    try {
        const response = await fetch(`${API_BASE_URL}/api/messages`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            },
            body: JSON.stringify({ receiver_id: currentConversation, content })
        });
        
        if (response.ok) {
            input.value = '';
            loadConversation(currentConversation);
        }
    } catch (error) {
        console.error('Error sending message:', error);
    }
}

// Utility Functions
function getBadgeClass(vitality, role) {
    if (role === 'admin' || role === 'super_admin') return 'admin';
    if (vitality >= 601) return 'lover';
    if (vitality >= 501) return 'enthusiast';
    if (vitality >= 401) return 'dedicated';
    if (vitality >= 301) return 'contributor';
    if (vitality >= 201) return 'active';
    if (vitality >= 101) return 'participant';
    return 'beginner';
}

function getBadgeName(vitality, role) {
    if (role === 'super_admin') return 'Main Admin';
    if (role === 'admin') return 'Admin';
    if (vitality >= 601) return 'Lover';
    if (vitality >= 501) return 'Enthusiast';
    if (vitality >= 401) return 'Dedicated';
    if (vitality >= 301) return 'Contributor';
    if (vitality >= 201) return 'Active';
    if (vitality >= 101) return 'Participant';
    return 'Beginner';
}

function setupEventListeners() {
    // Update preview in real-time
    const postContent = document.getElementById('post-content');
    const previewContent = document.getElementById('preview-content');
    
    if (postContent && previewContent) {
        postContent.addEventListener('input', () => {
            previewContent.innerHTML = renderMarkdown(postContent.value);
        });
    }
}

// 添加缺失的函数
async function likePost(postId) {
    if (!currentUser) {
        toggleAuth();
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE_URL}/api/posts/${postId}/like`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });
        
        if (response.ok) {
            loadPosts(); // 重新加载帖子
        }
    } catch (error) {
        console.error('Error liking post:', error);
    }
}

async function markUseful(postId) {
    if (!currentUser) {
        toggleAuth();
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE_URL}/api/posts/${postId}/useful`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });
        
        if (response.ok) {
            loadPosts(); // 重新加载帖子
        }
    } catch (error) {
        console.error('Error marking post useful:', error);
    }
}

async function showReplies(postId) {
    const container = document.getElementById(`replies-${postId}`);
    if (!container) return;
    
    container.classList.toggle('hidden');
    
    if (!container.classList.contains('hidden')) {
        try {
            const response = await fetch(`${API_BASE_URL}/api/posts/${postId}/replies`);
            if (response.ok) {
                const replies = await response.json();
                container.innerHTML = replies.map(reply => `
                    <div class="reply">
                        <div class="reply-author">
                            <strong>${reply.username}</strong>
                            <span class="badge ${getBadgeClass(reply.vitality, reply.role)}">
                                ${getBadgeName(reply.vitality, reply.role)}
                            </span>
                        </div>
                        <div class="reply-content">${reply.content}</div>
                        <div class="reply-date">${new Date(reply.created_at).toLocaleString()}</div>
                    </div>
                `).join('');
            }
        } catch (error) {
            console.error('Error loading replies:', error);
        }
    }
}

async function deletePost(postId) {
    if (!confirm('Are you sure you want to delete this post?')) return;
    
    try {
        const response = await fetch(`${API_BASE_URL}/api/posts/${postId}`, {
            method: 'DELETE',
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });
        
        if (response.ok) {
            loadPosts(); // 重新加载帖子
        }
    } catch (error) {
        console.error('Error deleting post:', error);
    }
}
