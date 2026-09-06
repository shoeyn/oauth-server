import { S3Client, ListObjectsV2Command, GetObjectCommand, PutObjectCommand, DeleteObjectCommand } from "@aws-sdk/client-s3";
import Redis from "ioredis";
import { ClientConfig } from "./types";

const S3_ENDPOINT = process.env.S3_ENDPOINT || "http://localhost:4566";
const S3_BUCKET = process.env.S3_BUCKET || "oauth2-clients";
const AWS_REGION = process.env.AWS_REGION || "us-east-1";
const REDIS_URL = process.env.REDIS_URL || "redis://localhost:6379";

export const s3 = new S3Client({
  endpoint: S3_ENDPOINT,
  region: AWS_REGION,
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID || "test",
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY || "test",
  },
  forcePathStyle: true,
});

let redisClient: Redis | null = null;
function getRedisClient(): Redis {
  if (!redisClient) {
    redisClient = new Redis(REDIS_URL, {
      lazyConnect: true,
      maxRetriesPerRequest: 1,
    });
  }
  return redisClient;
}

export async function notifySpringServer(action: string, clientId: string) {
  try {
    const client = getRedisClient();
    if (client.status !== "ready") {
      await client.connect();
    }
    await client.publish(
      "oauth2:clients:reload",
      JSON.stringify({ action, clientId, timestamp: new Date().toISOString() })
    );
    console.log(`[Redis Pub/Sub] Sent reload notification for client: ${clientId} (${action})`);
  } catch (err) {
    console.error("[Redis Pub/Sub] Failed to notify Spring server:", err);
  }
}

export async function listClients(): Promise<ClientConfig[]> {
  try {
    const listRes = await s3.send(
      new ListObjectsV2Command({
        Bucket: S3_BUCKET,
        Prefix: "clients/",
      })
    );

    if (!listRes.Contents || listRes.Contents.length === 0) {
      return [];
    }

    const clients: ClientConfig[] = [];
    for (const item of listRes.Contents) {
      if (!item.Key || !item.Key.endsWith(".json")) continue;
      try {
        const getRes = await s3.send(
          new GetObjectCommand({
            Bucket: S3_BUCKET,
            Key: item.Key,
          })
        );
        if (getRes.Body) {
          const bodyStr = await getRes.Body.transformToString();
          const parsed = JSON.parse(bodyStr) as ClientConfig;
          clients.push(parsed);
        }
      } catch (e) {
        console.error(`Failed to retrieve/parse ${item.Key}:`, e);
      }
    }
    return clients.sort((a, b) => a.clientId.localeCompare(b.clientId));
  } catch (err) {
    console.error("Error listing clients from S3:", err);
    return [];
  }
}

export async function getClient(clientId: string): Promise<ClientConfig | null> {
  try {
    const getRes = await s3.send(
      new GetObjectCommand({
        Bucket: S3_BUCKET,
        Key: `clients/${clientId}.json`,
      })
    );
    if (getRes.Body) {
      const bodyStr = await getRes.Body.transformToString();
      return JSON.parse(bodyStr) as ClientConfig;
    }
    return null;
  } catch {
    return null;
  }
}

export async function saveClient(client: ClientConfig): Promise<void> {
  const key = `clients/${client.clientId}.json`;
  await s3.send(
    new PutObjectCommand({
      Bucket: S3_BUCKET,
      Key: key,
      Body: JSON.stringify(client, null, 2),
      ContentType: "application/json",
    })
  );
  await notifySpringServer("save", client.clientId);
}

export async function deleteClient(clientId: string): Promise<void> {
  const key = `clients/${clientId}.json`;
  await s3.send(
    new DeleteObjectCommand({
      Bucket: S3_BUCKET,
      Key: key,
    })
  );
  await notifySpringServer("delete", clientId);
}
