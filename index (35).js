import express from 'express';
import session from 'express-session';
import { Client, GatewayIntentBits, PermissionsBitField } from 'discord.js';
import Groq from 'groq-sdk';
import fetch from 'node-fetch';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// =============== API CONFIGURATION ===============
// All API tokens and client IDs are configured here
const CONFIG = {
  // Discord Bot Configuration
  DISCORD_BOT_TOKEN: process.env.DISCORD_BOT_TOKEN,
  DISCORD_CLIENT_ID: process.env.DISCORD_CLIENT_ID,
  DISCORD_CLIENT_SECRET: process.env.DISCORD_CLIENT_SECRET,
  
  // Groq AI Configuration
  GROQ_API_KEY: process.env.GROQ_API_KEY,
  
  // Server Configuration
  PORT: process.env.PORT || 5000,
  SESSION_SECRET: process.env.SESSION_SECRET || 'discord-bot-dashboard-secret-key-change-in-production',
  NODE_ENV: process.env.NODE_ENV || 'development',
  
  // Replit Environment
  REPLIT_DEV_DOMAIN: process.env.REPLIT_DEV_DOMAIN,
  
  // Bot Settings
  COMMAND_PREFIX: '.',
  AI_MODEL: 'openai/gpt-oss-20b'
};

// Validate required environment variables
function validateConfig() {
  const required = [
    'DISCORD_BOT_TOKEN',
    'DISCORD_CLIENT_ID', 
    'DISCORD_CLIENT_SECRET',
    'GROQ_API_KEY'
  ];
  
  const missing = required.filter(key => !CONFIG[key]);
  
  if (missing.length > 0) {
    console.error('❌ Missing required environment variables:');
    missing.forEach(key => console.error(`   - ${key}`));
    console.error('\n📝 Please add these in Replit Secrets or your .env file');
    process.exit(1);
  }
  
  console.log('✅ All required API keys and tokens are configured');
}

// Validate configuration on startup
validateConfig();

// =============== DERIVED CONFIGURATION ===============
const BASE_URL = CONFIG.REPLIT_DEV_DOMAIN ? `https://${CONFIG.REPLIT_DEV_DOMAIN}` : `http://localhost:${CONFIG.PORT}`;
const OAUTH_REDIRECT_URI = `${BASE_URL}/auth/callback`;

const app = express();

// Set up Discord client
const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.MessageContent,
  ],
});

// Initialize Groq
const groq = new Groq({
  apiKey: CONFIG.GROQ_API_KEY
});

// Session configuration
app.set('trust proxy', 1);
app.use(session({
  secret: CONFIG.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: CONFIG.NODE_ENV === 'production',
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    httpOnly: true,
    sameSite: 'lax'
  }
}));

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set('view engine', 'ejs');
app.set('views', __dirname);

// Cache control to prevent browser caching in Replit environment
app.use((req, res, next) => {
  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  next();
});

// Load AI channels from file
const AI_CHANNELS_FILE = path.join(__dirname, 'ai_channels.json');
let aiChannels = new Map();

function loadAIChannels() {
  try {
    if (fs.existsSync(AI_CHANNELS_FILE)) {
      const data = JSON.parse(fs.readFileSync(AI_CHANNELS_FILE, 'utf8'));
      aiChannels = new Map(data);
    }
  } catch (error) {
    console.warn('Could not load AI channels:', error.message);
  }
}

function saveAIChannels() {
  try {
    fs.writeFileSync(AI_CHANNELS_FILE, JSON.stringify([...aiChannels]));
  } catch (error) {
    console.warn('Could not save AI channels:', error.message);
  }
}

// Load AI channels on startup
loadAIChannels();

function generateState() {
  return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
}

// Authentication middleware
function requireAuth(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/');
  }
  next();
}

// CSRF token generation and validation
function generateCSRF() {
  return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
}

function validateCSRF(req, res, next) {
  if (req.method === 'POST') {
    const token = req.body.csrf_token;
    const sessionToken = req.session.csrf_token;
    
    if (!token || !sessionToken || token !== sessionToken) {
      return res.status(403).send('Invalid CSRF token');
    }
  }
  next();
}

// Check if user has permission to manage a guild
function hasManageGuildPermission(userGuild) {
  const permissions = parseInt(userGuild.permissions);
  const MANAGE_GUILD = 0x00000020; // Manage Guild permission
  const ADMINISTRATOR = 0x00000008; // Administrator permission
  
  return (permissions & MANAGE_GUILD) === MANAGE_GUILD || 
         (permissions & ADMINISTRATOR) === ADMINISTRATOR ||
         userGuild.owner === true;
}

// Routes
app.get('/', (req, res) => {
  if (!req.session.user) {
    // Generate state for OAuth and store in session
    const state = generateState();
    req.session.oauth_state = state;
    
    const oauthURL = `https://discord.com/api/oauth2/authorize?client_id=${CONFIG.DISCORD_CLIENT_ID}&redirect_uri=${encodeURIComponent(OAUTH_REDIRECT_URI)}&response_type=code&scope=identify%20guilds&state=${state}`;
    
    return res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Discord Bot Dashboard - Login</title>
        <style>
          body { font-family: Arial, sans-serif; margin: 0; padding: 0; background-color: #1e293b; color: white; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
          .login-container { background-color: #334155; padding: 3rem; border-radius: 12px; box-shadow: 0 10px 25px rgba(0,0,0,0.3); text-align: center; max-width: 500px; }
          h1 { font-size: 2rem; margin-bottom: 1.5rem; color: #f1f5f9; }
          p { color: #cbd5e1; margin-bottom: 1rem; }
          .login-btn { background-color: #5865f2; color: white; padding: 0.75rem 2rem; border: none; border-radius: 8px; font-size: 1rem; font-weight: 600; text-decoration: none; display: inline-block; transition: background-color 0.2s; margin: 0.5rem; }
          .login-btn:hover { background-color: #4752c4; }
          .temp-btn { background-color: #059669; }
          .temp-btn:hover { background-color: #047857; }
          .setup-info { background-color: #1e293b; padding: 1rem; border-radius: 8px; margin: 1rem 0; font-size: 0.9rem; text-align: left; }
          .code { background-color: #0f172a; padding: 0.25rem 0.5rem; border-radius: 4px; color: #fbbf24; }
        </style>
      </head>
      <body>
        <div class="login-container">
          <h1>🤖 Discord AI Bot Dashboard</h1>
          <p>Choose your login method:</p>
          
          <a href="${oauthURL}" class="login-btn">Login with Discord OAuth</a>
          <br>
          <a href="/temp-access" class="login-btn temp-btn">Temporary Access (Skip OAuth)</a>
          
          <div class="setup-info">
            <strong>⚠️ OAuth Setup Required:</strong><br>
            If Discord login fails, add this redirect URI:<br>
            <span class="code">${OAUTH_REDIRECT_URI}</span><br><br>
            <strong>Steps:</strong><br>
            1. Go to <a href="https://discord.com/developers/applications" target="_blank" style="color: #60a5fa;">Discord Developer Portal</a><br>
            2. Select your application<br>
            3. Go to OAuth2 → General<br>
            4. Add the redirect URI above<br>
          </div>
        </div>
      </body>
      </html>
    `);
  }

  // Generate CSRF token
  req.session.csrf_token = generateCSRF();

  // Get user's guilds that the bot is also in
  const userGuilds = req.session.user.guilds || [];
  const botGuilds = Array.from(client.guilds.cache.values());
  
  const servers = botGuilds
    .filter(guild => {
      const userGuild = userGuilds.find(ug => ug.id === guild.id);
      return userGuild && hasManageGuildPermission(userGuild);
    })
    .map(guild => {
      const aiChannelId = aiChannels.get(guild.id);
      let aiChannelName = 'Not set';
      
      if (aiChannelId) {
        const channel = guild.channels.cache.get(aiChannelId);
        aiChannelName = channel ? `#${channel.name}` : 'Channel not found';
      }
      
      return {
        id: guild.id,
        name: guild.name,
        aiChannel: aiChannelName,
        channels: guild.channels.cache
          .filter(ch => ch.type === 0) // Text channels only
          .map(ch => ({ id: ch.id, name: ch.name }))
      };
    });

  res.render('index', { servers, csrf_token: req.session.csrf_token, user: req.session.user });
});

app.get('/temp-access', (req, res) => {
  // Create a temporary user session for testing
  req.session.user = {
    id: 'temp-user',
    username: 'TempUser',
    discriminator: '0000',
    avatar: null,
    guilds: Array.from(client.guilds.cache.values()).map(guild => ({
      id: guild.id,
      name: guild.name,
      permissions: '8', // Administrator permission for temp access
      owner: true
    }))
  };
  
  res.redirect('/');
});

app.get('/auth/callback', async (req, res) => {
  const { code, state, error, error_description } = req.query;
  
  // Handle OAuth errors
  if (error) {
    console.error('OAuth Error:', error, error_description);
    return res.send(`
      <!DOCTYPE html>
      <html>
      <head><title>OAuth Error</title></head>
      <body style="font-family: Arial; background: #1e293b; color: white; padding: 2rem; text-align: center;">
        <h1>🚫 OAuth Error</h1>
        <p><strong>Error:</strong> ${error}</p>
        <p><strong>Description:</strong> ${error_description || 'Unknown error'}</p>
        <p>Please check your Discord application OAuth settings.</p>
        <a href="/" style="color: #60a5fa;">← Back to Login</a>
      </body>
      </html>
    `);
  }
  
  // Verify state parameter
  if (!state || state !== req.session.oauth_state) {
    return res.send(`
      <!DOCTYPE html>
      <html>
      <head><title>Invalid State</title></head>
      <body style="font-family: Arial; background: #1e293b; color: white; padding: 2rem; text-align: center;">
        <h1>❌ Invalid State Parameter</h1>
        <p>OAuth state validation failed. This could be a security issue.</p>
        <a href="/" style="color: #60a5fa;">← Try Again</a>
      </body>
      </html>
    `);
  }
  
  if (!code) {
    return res.send(`
      <!DOCTYPE html>
      <html>
      <head><title>No Code</title></head>
      <body style="font-family: Arial; background: #1e293b; color: white; padding: 2rem; text-align: center;">
        <h1>❌ No Authorization Code</h1>
        <p>Discord didn't provide an authorization code.</p>
        <a href="/" style="color: #60a5fa;">← Try Again</a>
      </body>
      </html>
    `);
  }

  try {
    // Exchange code for access token
    const tokenResponse = await fetch('https://discord.com/api/oauth2/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        client_id: CONFIG.DISCORD_CLIENT_ID,
        client_secret: CONFIG.DISCORD_CLIENT_SECRET,
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: OAUTH_REDIRECT_URI,
      }),
    });

    const tokenData = await tokenResponse.json();
    
    if (!tokenResponse.ok) {
      console.error('Token exchange failed:', tokenData);
      return res.status(400).send('Failed to obtain access token');
    }

    // Get user information
    const userResponse = await fetch('https://discord.com/api/users/@me', {
      headers: {
        Authorization: `Bearer ${tokenData.access_token}`,
      },
    });

    const userData = await userResponse.json();
    
    // Get user's guilds
    const guildsResponse = await fetch('https://discord.com/api/users/@me/guilds', {
      headers: {
        Authorization: `Bearer ${tokenData.access_token}`,
      },
    });

    const guildsData = await guildsResponse.json();

    // Store user data in session
    req.session.user = {
      id: userData.id,
      username: userData.username,
      discriminator: userData.discriminator,
      avatar: userData.avatar,
      guilds: guildsData
    };

    // Clear OAuth state
    delete req.session.oauth_state;

    res.redirect('/');
  } catch (error) {
    console.error('OAuth callback error:', error);
    res.status(500).send('Authentication failed');
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Session destruction error:', err);
    }
    res.redirect('/');
  });
});

app.post('/setai', requireAuth, validateCSRF, (req, res) => {
  const { guildId, channelId } = req.body;
  
  if (!guildId || !channelId) {
    return res.status(400).send('Missing guild ID or channel ID');
  }

  // Verify user has access to this guild and proper permissions
  const userGuild = req.session.user.guilds.find(g => g.id === guildId);
  if (!userGuild) {
    return res.status(403).send('You do not have access to this guild');
  }
  
  if (!hasManageGuildPermission(userGuild)) {
    return res.status(403).send('You need Manage Guild permissions to configure the bot');
  }

  // Verify bot is in this guild
  const guild = client.guilds.cache.get(guildId);
  if (!guild) {
    return res.status(404).send('Bot is not in this guild');
  }

  // Verify channel exists
  const channel = guild.channels.cache.get(channelId);
  if (!channel) {
    return res.status(404).send('Channel not found');
  }

  // Store channel ID (not name) for persistence
  aiChannels.set(guildId, channelId);
  saveAIChannels();
  
  res.redirect('/');
});

app.post('/removeai', requireAuth, validateCSRF, (req, res) => {
  const { guildId } = req.body;
  
  if (!guildId) {
    return res.status(400).send('Missing guild ID');
  }

  // Verify user has access to this guild and proper permissions
  const userGuild = req.session.user.guilds.find(g => g.id === guildId);
  if (!userGuild) {
    return res.status(403).send('You do not have access to this guild');
  }
  
  if (!hasManageGuildPermission(userGuild)) {
    return res.status(403).send('You need Manage Guild permissions to configure the bot');
  }

  aiChannels.delete(guildId);
  saveAIChannels();
  
  res.redirect('/');
});

// Discord bot event handlers
client.once('ready', () => {
  console.log(`✅ Bot is online as ${client.user.tag}`);
  console.log(`🌐 Dashboard available at: ${BASE_URL}`);
  console.log(`🔧 Discord OAuth Redirect URI: ${OAUTH_REDIRECT_URI}`);
  console.log(`📝 Configure this exact URL in your Discord App OAuth2 settings:`);
  console.log(`   1. Go to https://discord.com/developers/applications`);
  console.log(`   2. Select your application`);
  console.log(`   3. Go to OAuth2 > General`);
  console.log(`   4. Add redirect URI: ${OAUTH_REDIRECT_URI}`);
});

client.on('messageCreate', async (message) => {
  // Ignore bot messages and DMs
  if (message.author.bot || !message.guild) return;

  const PREFIX = CONFIG.COMMAND_PREFIX;
  
  // Handle commands
  if (message.content.startsWith(PREFIX)) {
    const args = message.content.slice(PREFIX.length).trim().split(/ +/);
    const command = args.shift().toLowerCase();

    if (command === 'aiset') {
      // .aiset <channel>
      if (!message.member.permissions.has(PermissionsBitField.Flags.ManageGuild)) {
        return message.reply('❌ You need Manage Guild permissions to use this command.');
      }

      const channelMention = args[0];
      if (!channelMention) {
        return message.reply('❌ Please specify a channel. Usage: `.aiset #channel`');
      }

      // Parse channel mention or ID
      let channelId = channelMention.replace(/[<>#]/g, '');
      const channel = message.guild.channels.cache.get(channelId);
      
      if (!channel || channel.type !== 0) {
        return message.reply('❌ Invalid channel. Please mention a text channel.');
      }

      aiChannels.set(message.guild.id, channelId);
      saveAIChannels();
      
      return message.reply(`✅ AI channel set to ${channel}. I will now respond to all messages in that channel.`);
    }

    if (command === 'ask') {
      // .ask <prompt>
      const prompt = args.join(' ');
      if (!prompt) {
        return message.reply('❌ Please provide a question. Usage: `.ask your question here`');
      }

      try {
        await message.channel.sendTyping();

        // Create streaming completion
        const completion = await groq.chat.completions.create({
          model: CONFIG.AI_MODEL,
          messages: [
            {
              role: "user",
              content: prompt
            }
          ],
          temperature: 1,
          max_tokens: 1024,
          top_p: 1,
          stream: true
        });

        let fullResponse = '';
        let currentMessage = null;
        let messageContent = '';

        for await (const chunk of completion) {
          const content = chunk.choices[0]?.delta?.content || '';
          if (content) {
            fullResponse += content;
            messageContent += content;

            // Update message every 100 characters or if we hit Discord's limit
            if (messageContent.length >= 100 || messageContent.length >= 1900) {
              if (!currentMessage) {
                currentMessage = await message.reply(messageContent);
              } else {
                await currentMessage.edit(messageContent.slice(0, 1900));
              }
              
              // If we're approaching the limit, send a new message
              if (messageContent.length >= 1900) {
                currentMessage = null;
                messageContent = messageContent.slice(1900);
              }
            }
          }
        }

        // Send final message if there's remaining content
        if (messageContent && !currentMessage) {
          await message.reply(messageContent);
        } else if (messageContent && currentMessage) {
          await currentMessage.edit(messageContent);
        }

      } catch (error) {
        console.error('Error with .ask command:', error);
        await message.reply('❌ Sorry, I encountered an error while processing your question.');
      }
      return;
    }

    if (command === 'help') {
      const helpEmbed = {
        title: '🤖 AI Bot Commands',
        description: 'Available commands for the AI bot:',
        fields: [
          {
            name: '`.aiset #channel`',
            value: 'Set a channel where I will automatically respond to all messages (requires Manage Guild permission)',
            inline: false
          },
          {
            name: '`.ask <question>`',
            value: 'Ask me any question and I\'ll respond with AI-generated answer',
            inline: false
          },
          {
            name: '`.help`',
            value: 'Show this help message',
            inline: false
          }
        ],
        color: 0x5865F2,
        footer: {
          text: 'AI Bot powered by Groq'
        }
      };
      
      return message.reply({ embeds: [helpEmbed] });
    }
    
    return; // Don't process commands as regular AI messages
  }

  // Auto AI response in AI channel (only if not a command)
  const aiChannelId = aiChannels.get(message.guild.id);
  if (!aiChannelId || message.channel.id !== aiChannelId) return;
  
  // Ensure channel is a text channel
  if (message.channel.type !== 0) return;

  try {
    // Show typing indicator
    await message.channel.sendTyping();

    // Create streaming completion for auto responses
    const completion = await groq.chat.completions.create({
      model: CONFIG.AI_MODEL,
      messages: [
        {
          role: "system",
          content: "You are a helpful Discord bot assistant. Keep responses concise and friendly."
        },
        {
          role: "user",
          content: message.content
        }
      ],
      temperature: 1,
      max_tokens: 512,
      top_p: 1,
      stream: true
    });

    let fullResponse = '';
    let currentMessage = null;
    let messageContent = '';

    for await (const chunk of completion) {
      const content = chunk.choices[0]?.delta?.content || '';
      if (content) {
        fullResponse += content;
        messageContent += content;

        // Update message every 50 characters for auto responses
        if (messageContent.length >= 50 || messageContent.length >= 1900) {
          if (!currentMessage) {
            currentMessage = await message.reply(messageContent);
          } else {
            await currentMessage.edit(messageContent.slice(0, 1900));
          }
          
          // If we're approaching the limit, send a new message
          if (messageContent.length >= 1900) {
            currentMessage = null;
            messageContent = messageContent.slice(1900);
          }
        }
      }
    }

    // Send final message if there's remaining content
    if (messageContent && !currentMessage) {
      await message.reply(messageContent);
    } else if (messageContent && currentMessage) {
      await currentMessage.edit(messageContent);
    }

  } catch (error) {
    console.error('Error generating AI response:', error);
    await message.reply('Sorry, I encountered an error while processing your message.');
  }
});

// Error handling
client.on('error', console.error);
process.on('unhandledRejection', console.error);

// Start the application
async function start() {
  try {
    // Start Express server
    app.listen(CONFIG.PORT, '0.0.0.0', () => {
      console.log(`🚀 Server running on port ${CONFIG.PORT}`);
    });

    // Login Discord bot
    await client.login(CONFIG.DISCORD_BOT_TOKEN);
  } catch (error) {
    console.error('Failed to start application:', error);
    process.exit(1);
  }
}

start();