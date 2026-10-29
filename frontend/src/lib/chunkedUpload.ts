import { encryptFile } from './encryption';
import { BACKEND_URL } from './api';

const CHUNK_SIZE = 1 * 1024 * 1024; // 1 MB per transfer chunk (encryption is whole-file)
const MAX_PARALLEL = 3;              // Upload 3 chunks simultaneously
const MAX_RETRIES = 3;               // Retry failed chunks up to 3 times

export interface UploadProgress {
    chunksTotal: number;
    chunksUploaded: number;
    chunksFailed: number;
    percentage: number;
    phase: 'encrypting' | 'uploading' | 'finalizing' | 'done' | 'error';
    currentChunk?: number;
}

type ProgressCallback = (progress: UploadProgress) => void;

/**
 * Upload a file in parallel transfer chunks.
 *
 * Flow:
 *   1. Encrypt the WHOLE file as a single AES-GCM blob (same as single-shot upload)
 *   2. Split the encrypted ciphertext into CHUNK_SIZE transfer chunks
 *   3. Upload chunks in batches of MAX_PARALLEL (parallel)
 *   4. Retry failed chunks up to MAX_RETRIES times
 *   5. Call /chunks/finalize to reassemble on server
 *
 * This ensures the assembled ciphertext on the server is one contiguous AES-GCM blob
 * that can be decrypted with a single pass using the stored IV — exactly what the
 * download page does.
 *
 * @returns The file record returned by /chunks/finalize
 */
export async function uploadFileInChunks(
    file: File,
    key: CryptoKey,
    _baseIV: Uint8Array,       // kept for API compatibility, no longer used
    _ivBase64: string,         // will be overwritten with the real IV from encryptFile
    token: string,
    onProgress: ProgressCallback
): Promise<{ id: string; filename: string; file_hash: string }> {

    const sessionId = crypto.randomUUID();

    // ── Phase 1: Encrypt the ENTIRE file as one AES-GCM blob ─────────────────
    onProgress({
        chunksTotal: 1,
        chunksUploaded: 0,
        chunksFailed: 0,
        percentage: 10,
        phase: 'encrypting',
    });

    // encryptFile generates its own random IV internally and returns it
    const { file: encryptedFile, iv: actualIvBase64 } = await encryptFile(file, key);
    const encryptedBuffer = await encryptedFile.arrayBuffer();

    const totalChunks = Math.ceil(encryptedBuffer.byteLength / CHUNK_SIZE);

    // ── Phase 2: Split encrypted ciphertext into transfer chunks ──────────────
    const chunks: { index: number; buffer: ArrayBuffer }[] = [];
    for (let i = 0; i < totalChunks; i++) {
        const start = i * CHUNK_SIZE;
        const end = Math.min(start + CHUNK_SIZE, encryptedBuffer.byteLength);
        chunks.push({ index: i, buffer: encryptedBuffer.slice(start, end) });
    }

    let chunksUploaded = 0;
    let chunksFailed = 0;

    // ── Phase 3: Upload chunks in parallel batches ────────────────────────────
    const uploadChunk = async (chunkInfo: { index: number; buffer: ArrayBuffer }, attempt = 1): Promise<void> => {
        onProgress({
            chunksTotal: totalChunks,
            chunksUploaded,
            chunksFailed,
            percentage: 10 + Math.round((chunksUploaded / totalChunks) * 75), // 10–85%
            phase: 'uploading',
            currentChunk: chunkInfo.index,
        });

        const formData = new FormData();
        formData.append(
            'chunk',
            new Blob([chunkInfo.buffer], { type: 'application/octet-stream' }),
            `chunk_${chunkInfo.index}`
        );
        formData.append('sessionId', sessionId);
        formData.append('chunkIndex', String(chunkInfo.index));
        formData.append('totalChunks', String(totalChunks));

        const res = await fetch(`${BACKEND_URL}/chunks/upload`, {
            method: 'POST',
            headers: { Authorization: `Bearer ${token}` },
            body: formData,
        });

        if (!res.ok) {
            const err = await res.json().catch(() => ({ error: 'Upload failed' }));
            if (attempt <= MAX_RETRIES) {
                console.warn(`[chunkedUpload] Chunk ${chunkInfo.index} failed (attempt ${attempt}/${MAX_RETRIES}): ${err.error}. Retrying...`);
                await delay(500 * attempt);
                return uploadChunk(chunkInfo, attempt + 1);
            } else {
                chunksFailed++;
                throw new Error(`Chunk ${chunkInfo.index} failed after ${MAX_RETRIES} retries: ${err.error}`);
            }
        }

        chunksUploaded++;
    };

    // Run in sliding window batches
    for (let i = 0; i < chunks.length; i += MAX_PARALLEL) {
        const batch = chunks.slice(i, i + MAX_PARALLEL);
        await Promise.all(batch.map(c => uploadChunk(c)));

        onProgress({
            chunksTotal: totalChunks,
            chunksUploaded,
            chunksFailed,
            percentage: 10 + Math.round((chunksUploaded / totalChunks) * 75),
            phase: 'uploading',
        });
    }

    // ── Phase 4: Finalize (reassemble on server) ──────────────────────────────
    onProgress({
        chunksTotal: totalChunks,
        chunksUploaded,
        chunksFailed,
        percentage: 85,
        phase: 'finalizing',
    });

    const finalizeRes = await fetch(`${BACKEND_URL}/chunks/finalize`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
            sessionId,
            totalChunks,
            filename: file.name,
            iv: actualIvBase64,  // ← Use the IV from encryptFile, not the base IV
        }),
    });

    if (!finalizeRes.ok) {
        const err = await finalizeRes.json().catch(() => ({ error: 'Finalize failed' }));
        throw new Error(err.error || 'Finalize request failed');
    }

    const result = await finalizeRes.json();

    onProgress({
        chunksTotal: totalChunks,
        chunksUploaded,
        chunksFailed,
        percentage: 100,
        phase: 'done',
    });

    return result.file;
}

function delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
}
