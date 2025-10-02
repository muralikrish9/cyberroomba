import { MongoClient, Db } from 'mongodb';
import { config } from './config.js';

let client: MongoClient | null = null;
let cachedDb: Db | null = null;

export async function connectToDatabase(): Promise<Db> {
  if (!client) {
    client = new MongoClient(config.mongodbUri);
  }
  if (!cachedDb) {
    try {
      await client.connect();
      cachedDb = client.db(config.mongodbDb);
      console.log(`[db] Connected to MongoDB: ${config.mongodbDb}`);
    } catch (error) {
      console.error(`[db] Failed to connect to MongoDB: ${(error as Error).message}`);
      throw new Error(`MongoDB connection failed: ${(error as Error).message}`);
    }
  }
  return cachedDb;
}

export async function withDb<T>(fn: (db: Db) => Promise<T>): Promise<T> {
  const db = await connectToDatabase();
  return fn(db);
}

export async function closeDatabase(): Promise<void> {
  if (client) {
    await client.close();
    client = null;
    cachedDb = null;
  }
}
