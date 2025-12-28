// Configuration
const API_BASE_URL = process.env.REACT_APP_API_URL || 'https://your-backend.onrender.com';

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
    checkAuth();
    loadPosts();
    setupEventListeners();
});

// Auth Functions
function toggleAuth() {
    const modal = document.getElementById('auth-modal');
    modal.classList.toggle('hidden');
}

function toggleAuthType() {
    const title = document.getElementById('auth-title');
    const toggle = document.getElementById('auth-toggle');
    const emailInput = document.getElementById('auth-email');
    const confirmInput = document.getElementById('auth-confirm-password');
    
    if (title.textContent === 'Login') {
        title.textContent = 'Register';
        toggle.innerHTML = 'Already have an account? <a href="#" onclick="toggleAuthType()">Login</a>';
        emailInput.classList.remove('hidden');
        confirmInput.classList.remove('hidden');
    } else {
        title.textContent = 'Login';
        toggle.innerHTML = 'Don\'t have an account? <a href="#" onclick="toggleAuthType()">Register</a>';
        emailInput.classList.add('hidden');
        confirmInput.classList.add('hidden');
    }
}

async function handleAuth() {
    const username = document.getElementById('auth-username').value;
    const email = document.getElementById('auth-email').value;
    const password = document.getElementById('auth-password').value;
    const confirm = document.getElementById('auth-confirm-password').value;
    const isRegister = document.getElementById('auth-title').textContent === 'Register';
    
    if (isRegister) {
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
            
            if (currentUser.role === 'admin' || currentUser.role === 'super_admin') {
                document.getElementById('admin-panel').classList.remove('hidden');
            }
        } else {
            alert('Login failed');
        }
    } catch (error) {
        console.error('Login error:', error);
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
            alert('Registration successful! Please login.');
            toggleAuthType();
        } else {
            alert('Registration failed');
        }
    } catch (error) {
        console.error('Register error:', error);
    }
}

function logout() {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    authToken = null;
    currentUser = null;
    updateUI();
    showSection('home');
}

function checkAuth() {
    const token = localStorage.getItem('token');
    const user = localStorage.getItem('user');
    
    if (token && user) {
        authToken = token;
        currentUser = JSON.parse(user);
        updateUI();
    }
}

function updateUI() {
    const authLink = document.getElementById('auth-link');
    if (currentUser) {
        authLink.textContent = 'Logout';
        authLink.onclick = logout;
        document.getElementById('profile-username').textContent = currentUser.username;
    } else {
        authLink.textContent = 'Login';
        authLink.onclick = toggleAuth;
    }
}

// Navigation
function showSection(sectionName) {
    Object.values(sections).forEach(section => section.classList.add('hidden'));
    sections[sectionName].classList.remove('hidden');
    
    if (sectionName === 'profile' && currentUser) {
        loadProfile();
    } else if (sectionName === 'posts') {
        loadPosts();
    } else if (sectionName === 'messages') {
        loadConversations();
    }
}

// Post Functions
async function loadPosts() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/posts`);
        posts = await response.json();
        renderPosts();
    } catch (error) {
        console.error('Error loading posts:', error);
    }
}

function renderPosts() {
    const container = document.getElementById('posts-container');
    container.innerHTML = posts.map(post => `
        <div class="post" data-id="${post.id}">
            <div class="post-header">
                <div class="post-author">
                    <span class="username">${post.author.username}</span>
                    <span class="badge ${getBadgeClass(post.author.vitality, post.author.role)}">
                        ${getBadgeName(post.author.vitality, post.author.role)}
                    </span>
                </div>
                <span class="post-date">${new Date(post.created_at).toLocaleDateString()}</span>
            </div>
            <h3 class="post-title">${post.title}</h3>
            <div class="post-content">${renderMarkdown(post.content)}</div>
            <div class="post-actions">
                <button class="action-button" onclick="likePost(${post.id})">
                    <i class="fas fa-thumbs-up"></i>
                    <span>${post.likes_count}</span>
                </button>
                <button class="action-button" onclick="markUseful(${post.id})">
                    <i class="fas fa-check-circle"></i>
                    <span>${post.useful_count}</span>
                </button>
                <button class="action-button" onclick="showReplies(${post.id})">
                    <i class="fas fa-comment"></i>
                    <span>${post.replies_count}</span>
                </button>
                ${currentUser && (currentUser.role === 'admin' || currentUser.role === 'super_admin') ? `
                    <button class="action-button danger" onclick="deletePost(${post.id})">
                        <i class="fas fa-trash"></i>
                    </button>
                ` : ''}
            </div>
            <div id="replies-${post.id}" class="replies-container hidden"></div>
        </div>
    `).join('');
}

async function createPost() {
    if (!currentUser) {
        alert('Please login to create a post');
        return;
    }
    
    const title = document.getElementById('post-title').value;
    const content = document.getElementById('post-content').value;
    
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
        }
    } catch (error) {
        console.error('Error creating post:', error);
    }
}

// Markdown and LaTeX Rendering
function renderMarkdown(text) {
    const html = marked.parse(text);
    return html.replace(/\$\$(.*?)\$\$/g, (match, latex) => {
        try {
            return katex.renderToString(latex, { throwOnError: false });
        } catch (e) {
            return match;
        }
    });
}

function formatText(type) {
    const textarea = document.getElementById('post-content');
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
        const userData = await response.json();
        
        document.getElementById('profile-vitality').textContent = userData.vitality;
        document.getElementById('profile-bio').value = userData.bio || '';
        document.getElementById('profile-signature').value = userData.signature || '';
        
        const badge = document.getElementById('profile-badge');
        badge.className = `badge ${getBadgeClass(userData.vitality, userData.role)}`;
        badge.textContent = getBadgeName(userData.vitality, userData.role);
    } catch (error) {
        console.error('Error loading profile:', error);
    }
}

async function updateProfile() {
    const bio = document.getElementById('profile-bio').value;
    const signature = document.getElementById('profile-signature').value;
    
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
        }
    } catch (error) {
        console.error('Error updating profile:', error);
    }
}

// Message Functions
async function loadConversations() {
    if (!currentUser) return;
    
    try {
        const response = await fetch(`${API_BASE_URL}/api/messages/conversations`, {
            headers: { 'Authorization': `Bearer ${authToken}` }
        });
        conversations = await response.json();
        renderConversations();
    } catch (error) {
        console.error('Error loading conversations:', error);
    }
}

function renderConversations() {
    const container = document.getElementById('conversations-list');
    container.innerHTML = conversations.map(conv => `
        <div class="conversation-item" onclick="loadConversation(${conv.user.id})">
            <div class="conv-user">${conv.user.username}</div>
            <div class="conv-preview">${conv.last_message?.content?.substring(0, 50) || ''}</div>
        </div>
    `).join('');
}

async function loadConversation(userId) {
    try {
        const response = await fetch(`${API_BASE_URL}/api/messages/${userId}`, {
            headers: { 'Authorization': `Bearer ${authToken}` }
        });
        const messages = await response.json();
        renderMessages(messages);
        currentConversation = userId;
    } catch (error) {
        console.error('Error loading conversation:', error);
    }
}

function renderMessages(messages) {
    const container = document.getElementById('chat-messages');
    container.innerHTML = messages.map(msg => `
        <div class="message ${msg.sender_id === currentUser.id ? 'sent' : 'received'}">
            <div class="message-content">${msg.content}</div>
            <div class="message-time">${new Date(msg.created_at).toLocaleTimeString()}</div>
        </div>
    `).join('');
    container.scrollTop = container.scrollHeight;
}

async function sendMessage() {
    if (!currentConversation) return;
    
    const input = document.getElementById('message-input');
    const content = input.value.trim();
    
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
    if (postContent) {
        postContent.addEventListener('input', () => {
            document.getElementById('preview-content').innerHTML = 
                renderMarkdown(postContent.value);
        });
    }
}
