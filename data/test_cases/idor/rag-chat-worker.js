// rag-chat-worker.js
// Worker for the 'rag-chat-processing' queue: uploads a document to the
// FastAPI RAG service (if not already uploaded), waits for ingestion, then
// asks a question and returns the answer + sources.

const { Worker, UnrecoverableError } = require('bullmq');
const { connection } = require('./queue');
const { uploadDocument, waitForJob, chat } = require('./rag-client');

const ragChatWorker = new Worker(
  'rag-chat-processing',
  async (job) => {
    // documentId: pass this in if the document was already uploaded/ingested
    // in an earlier job (e.g. a follow-up question) to skip re-uploading.
    const { filePath, filename, question, topK, documentId: existingDocumentId } = job.data;

    try {
      let documentId = existingDocumentId;

      if (!documentId) {
        await job.updateProgress({ stage: 'uploading', percent: 5 });
        const upload = await uploadDocument(filePath, filename);
        documentId = upload.document_id;

        await job.updateProgress({ stage: 'ingesting', percent: 10 });
        await waitForJob(upload.job_id, {
          onProgress: (ingestJob) => {
            // Scale the RAG API's 0-100 ingestion progress into this job's
            // 10-80% slice, so the frontend sees smooth progress across the
            // whole upload -> ingest -> answer sequence, not two separate bars.
            const scaled = 10 + Math.round(((ingestJob.progress || 0) / 100) * 70);
            job.updateProgress({ stage: 'ingesting', percent: scaled });
          },
        });
      }

      await job.updateProgress({ stage: 'asking', percent: 85 });
      const result = await chat(documentId, question, topK || 5);

      await job.updateProgress({ stage: 'completed', percent: 100 });
      return { documentId, answer: result.answer, sources: result.sources };
    } catch (err) {
      console.error(`[RAG Chat Worker] ❌ Error: ${err.message}`);
      if (err.isRagDeadLetter) {
        // The RAG API already retried this internally and gave up - don't
        // have BullMQ retry the whole upload+ingest+chat sequence on top of
        // that (that would just re-upload the same doomed file 3 more times).
        throw new UnrecoverableError(err.message);
      }
      throw err;
    }
  },
  { connection, lockDuration: 900000, concurrency: 2 }
);

ragChatWorker.on('completed', (job) => console.log(`🎉 RAG Chat Job ${job.id} completed.`));
ragChatWorker.on('failed', (job, err) => console.error(`🔥 RAG Chat Job ${job.id} failed: ${err.message}`));

module.exports = { ragChatWorker };
