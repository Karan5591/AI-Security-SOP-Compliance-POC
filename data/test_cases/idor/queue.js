const { Queue } = require('bullmq');
const IORedis = require('ioredis');

const connection = new IORedis({ host: '127.0.0.1', port: 6379, maxRetriesPerRequest:null ,enableReadyCheck: false,
  retryDelayOnFailover: 100,
  maxLoadingRetryTime: 10000,
  lazyConnect: true,
  commandTimeout: 30000,
  connectTimeout: 10000});

  // Connection event handlers
connection.on('connect', () => {
  console.log('✅ Redis connected - queue.js');
});

connection.on('ready', () => {
  console.log('⚡ Redis ready for commands - queue.js');
});

connection.on('error', (err) => {
  console.error('❌ Redis connection error - queue.js:', err.message);
});

connection.on('end', () => {
  console.error('🔌 Redis connection closed - queue.js');
});

// Test connection
connection.ping().then(() => {
  console.log('🎯 Redis connection test successful - queue.js');
}).catch(err => {
  console.error('❌ Redis connection test failed - queue.js:', err);
});

// Consistent queue configuration across all servers
const defaultQueueOptions = {
  connection,
  defaultJobOptions: {
    removeOnComplete: 100,     // Keep last 100 completed jobs
    removeOnFail: 50,          // Keep last 50 failed jobs
    attempts: 3,               // Retry failed jobs 3 times
    backoff: {
      type: 'exponential',     // Exponential backoff
      delay: 1000,             // Start with 1 second delay
    },
    lockDuration: 300000,      // 5 minutes lock duration - CRITICAL
    timeout: 600000,           // 10 minutes overall timeout
  }
};

// FIX: BullMQ's Queue constructor is `new Queue(name, options)` - options
// must be passed directly, not nested under a key. The previous version
// (`new Queue('file-processing', { defaultQueueOptions })`) wrapped it
// under a `defaultQueueOptions` property, so `connection` never actually
// reached BullMQ for any of these four queues.
const fileQueue = new Queue('file-processing', defaultQueueOptions);
const nonOcrQueue = new Queue('non-ocr-processing', defaultQueueOptions);
const ocrQueue = new Queue('ocrQueue', defaultQueueOptions);
const autoOcrQueue = new Queue("myocrQueue", defaultQueueOptions);

// New queue for the RAG "chat with document" integration.
const ragChatQueue = new Queue('rag-chat-processing', defaultQueueOptions);

// FIX: `connection` was used elsewhere (non-ocr-queue.js, ocr-queue.js,
// ocr-worker.js all do `const { connection } = require('./queue')`) but was
// never exported, so it was `undefined` in every one of those files.
module.exports = { connection, fileQueue, nonOcrQueue, ocrQueue, autoOcrQueue, ragChatQueue, defaultQueueOptions };
