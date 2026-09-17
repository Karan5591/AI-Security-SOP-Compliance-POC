// rag-client.js
// Talks to the FastAPI "chat with document" (RAG) service - upload a PDF,
// wait for it to finish ingesting, then ask questions against it.

const axios = require('axios');
const FormData = require('form-data');
const fs = require('fs');
const path = require('path');
const https = require('https');

const RAG_API_BASE_URL = process.env.RAG_API_BASE_URL || 'http://localhost:8000';
const RAG_API_KEY = process.env.RAG_API_KEY;

// Only set RAG_TLS_INSECURE=true if the RAG service sits behind a
// self-signed cert you genuinely can't add to Node's trust store.
// Defaults to verifying TLS like any normal HTTPS client - don't disable
// this globally the way NODE_TLS_REJECT_UNAUTHORIZED does elsewhere in
// this codebase; that turns off verification for every HTTPS call in the
// whole process, not just this one.
const RAG_TLS_INSECURE = process.env.RAG_TLS_INSECURE === 'true';

if (!RAG_API_KEY) {
  console.warn('⚠️  RAG_API_KEY is not set - calls to the RAG service will get 401s.');
}

const httpsAgent = RAG_TLS_INSECURE ? new https.Agent({ rejectUnauthorized: false }) : undefined;

const ragHttp = axios.create({
  baseURL: RAG_API_BASE_URL,
  httpsAgent,
  headers: { 'X-API-Key': RAG_API_KEY },
});

async function checkHealth() {
  const response = await ragHttp.get('/health', { timeout: 5000 });
  return response.data;
}

async function uploadDocument(filePath, filename) {
  const form = new FormData();
  form.append('file', fs.createReadStream(filePath), filename || path.basename(filePath));

  const response = await ragHttp.post('/api/v1/documents', form, {
    headers: { ...form.getHeaders(), 'X-API-Key': RAG_API_KEY },
    maxContentLength: Infinity,
    maxBodyLength: Infinity,
    timeout: 60000,
  });
  // { document_id, filename, job_id, status: 'queued' }
  return response.data;
}

async function getJobStatus(jobId) {
  const response = await ragHttp.get(`/api/v1/jobs/${jobId}`, { timeout: 15000 });
  return response.data;
}

/**
 * Poll an ingestion job until it reaches a terminal state.
 *
 * Ingestion (OCR + chunking + embedding) can genuinely take minutes for a
 * large PDF, so this polls periodically with a generous ceiling instead of
 * blocking on one long HTTP request that could time out well before the
 * job actually finishes.
 *
 * A `dead_letter` status means the RAG API's own worker already retried
 * this job internally (up to 4 attempts) and gave up - that's a permanent
 * failure, not a transient one, so it's marked on the thrown error via
 * `isRagDeadLetter` so callers (see rag-chat-worker.js) can choose not to
 * retry the whole thing again on top of retries that already happened.
 */
async function waitForJob(jobId, { timeoutMs = 10 * 60 * 1000, intervalMs = 3000, onProgress } = {}) {
  const startedAt = Date.now();
  // eslint-disable-next-line no-constant-condition
  while (true) {
    const job = await getJobStatus(jobId);
    if (onProgress) onProgress(job);

    if (job.status === 'completed') return job;

    if (job.status === 'dead_letter') {
      const error = new Error(
        `RAG job ${jobId} failed permanently after ${job.max_attempts || '?'} attempts: ${job.error || 'unknown error'}`
      );
      error.isRagDeadLetter = true;
      throw error;
    }

    if (Date.now() - startedAt > timeoutMs) {
      throw new Error(`Timed out waiting for RAG job ${jobId} (last status: ${job.status})`);
    }

    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
}

async function chat(documentId, question, topK = 5) {
  const response = await ragHttp.post(
    '/api/v1/chat',
    { document_id: documentId, question, top_k: topK },
    { timeout: 120000 }
  );
  // { document_id, answer, sources }
  return response.data;
}

module.exports = { checkHealth, uploadDocument, getJobStatus, waitForJob, chat };
