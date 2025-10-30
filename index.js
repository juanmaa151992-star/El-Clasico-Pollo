var __defProp = Object.defineProperty;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __esm = (fn, res) => function __init() {
  return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// shared/schema.ts
var schema_exports = {};
__export(schema_exports, {
  insertOrderItemSchema: () => insertOrderItemSchema,
  insertOrderSchema: () => insertOrderSchema,
  insertProductSchema: () => insertProductSchema,
  insertRestaurantSchema: () => insertRestaurantSchema,
  insertRewardRedemptionSchema: () => insertRewardRedemptionSchema,
  insertRewardSchema: () => insertRewardSchema,
  orderItems: () => orderItems,
  orders: () => orders,
  products: () => products,
  restaurants: () => restaurants,
  rewardRedemptions: () => rewardRedemptions,
  rewards: () => rewards,
  sessions: () => sessions,
  users: () => users
});
import { sql } from "drizzle-orm";
import {
  pgTable,
  text,
  varchar,
  integer,
  decimal,
  timestamp,
  jsonb,
  index
} from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
var sessions, users, restaurants, products, orders, orderItems, rewards, rewardRedemptions, insertRestaurantSchema, insertProductSchema, insertOrderSchema, insertOrderItemSchema, insertRewardSchema, insertRewardRedemptionSchema;
var init_schema = __esm({
  "shared/schema.ts"() {
    "use strict";
    sessions = pgTable(
      "sessions",
      {
        sid: varchar("sid").primaryKey(),
        sess: jsonb("sess").notNull(),
        expire: timestamp("expire").notNull()
      },
      (table) => [index("IDX_session_expire").on(table.expire)]
    );
    users = pgTable("users", {
      id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
      email: varchar("email").unique().notNull(),
      password: varchar("password"),
      // For local auth (hashed)
      firstName: varchar("firstName"),
      lastName: varchar("lastName"),
      profileImageUrl: varchar("profileImageUrl"),
      points: integer("points").notNull().default(0),
      isAdmin: integer("is_admin").notNull().default(0),
      // 1 = admin, 0 = regular user
      createdAt: timestamp("createdAt").defaultNow(),
      updatedAt: timestamp("updatedAt").defaultNow()
    });
    restaurants = pgTable("restaurants", {
      id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
      name: text("name").notNull(),
      image: text("image").notNull(),
      rating: decimal("rating", { precision: 2, scale: 1 }).notNull().default("4.5"),
      reviewCount: integer("review_count").notNull().default(0),
      deliveryTime: text("delivery_time").notNull(),
      deliveryFee: integer("delivery_fee").notNull(),
      minOrder: integer("min_order").notNull(),
      categories: text("categories").array().notNull(),
      promotion: text("promotion")
    });
    products = pgTable("products", {
      id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
      restaurantId: varchar("restaurant_id").notNull().references(() => restaurants.id),
      name: text("name").notNull(),
      description: text("description").notNull(),
      price: integer("price").notNull(),
      image: text("image").notNull(),
      category: text("category")
    });
    orders = pgTable("orders", {
      id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
      userId: varchar("user_id").notNull().references(() => users.id),
      restaurantId: varchar("restaurant_id").notNull().references(() => restaurants.id),
      status: text("status").notNull().default("placed"),
      paymentMethod: text("payment_method").notNull().default("cash"),
      subtotal: integer("subtotal").notNull(),
      deliveryFee: integer("delivery_fee").notNull(),
      serviceFee: integer("service_fee").notNull(),
      total: integer("total").notNull(),
      deliveryAddress: text("delivery_address").notNull(),
      createdAt: timestamp("created_at").notNull().defaultNow()
    });
    orderItems = pgTable("order_items", {
      id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
      orderId: varchar("order_id").notNull().references(() => orders.id),
      productId: varchar("product_id").notNull().references(() => products.id),
      productName: text("product_name").notNull(),
      productPrice: integer("product_price").notNull(),
      productImage: text("product_image").notNull(),
      quantity: integer("quantity").notNull()
    });
    rewards = pgTable("rewards", {
      id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
      name: text("name").notNull(),
      description: text("description").notNull(),
      pointsCost: integer("points_cost").notNull(),
      image: text("image").notNull(),
      type: text("type").notNull(),
      // 'discount' or 'product'
      value: integer("value").notNull(),
      // discount amount or product price
      stock: integer("stock").notNull().default(-1),
      // -1 means unlimited
      active: integer("active").notNull().default(1)
      // 1 = active, 0 = inactive
    });
    rewardRedemptions = pgTable("reward_redemptions", {
      id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
      userId: varchar("user_id").notNull().references(() => users.id),
      rewardId: varchar("reward_id").notNull().references(() => rewards.id),
      rewardName: text("reward_name").notNull(),
      pointsSpent: integer("points_spent").notNull(),
      status: text("status").notNull().default("pending"),
      // pending, used, expired
      redeemedAt: timestamp("redeemed_at").notNull().defaultNow(),
      usedAt: timestamp("used_at")
    });
    insertRestaurantSchema = createInsertSchema(restaurants).omit({
      id: true
    });
    insertProductSchema = createInsertSchema(products).omit({
      id: true
    });
    insertOrderSchema = createInsertSchema(orders).omit({
      id: true,
      createdAt: true,
      userId: true
    });
    insertOrderItemSchema = createInsertSchema(orderItems).omit({
      id: true
    });
    insertRewardSchema = createInsertSchema(rewards).omit({
      id: true
    });
    insertRewardRedemptionSchema = createInsertSchema(rewardRedemptions).omit({
      id: true,
      redeemedAt: true
    });
  }
});

// server/db.ts
import { Pool, neonConfig } from "@neondatabase/serverless";
import { drizzle } from "drizzle-orm/neon-serverless";
import ws from "ws";
var pool, db;
var init_db = __esm({
  "server/db.ts"() {
    "use strict";
    init_schema();
    neonConfig.webSocketConstructor = ws;
    if (!process.env.DATABASE_URL) {
      throw new Error(
        "DATABASE_URL must be set. Did you forget to provision a database?"
      );
    }
    pool = new Pool({ connectionString: process.env.DATABASE_URL });
    db = drizzle({ client: pool, schema: schema_exports });
  }
});

// server/storage.ts
var storage_exports = {};
__export(storage_exports, {
  DbStorage: () => DbStorage,
  storage: () => storage
});
import { eq, desc, sql as sql2 } from "drizzle-orm";
var DbStorage, storage;
var init_storage = __esm({
  "server/storage.ts"() {
    "use strict";
    init_schema();
    init_db();
    DbStorage = class {
      // Users (supports both Replit Auth and local auth)
      async getUser(id) {
        const [user] = await db.select().from(users).where(eq(users.id, id));
        return user;
      }
      async getUserByEmail(email) {
        const [user] = await db.select().from(users).where(eq(users.email, email));
        return user;
      }
      async upsertUser(userData) {
        const [user] = await db.insert(users).values(userData).onConflictDoUpdate({
          target: users.id,
          set: {
            ...userData,
            updatedAt: /* @__PURE__ */ new Date()
          }
        }).returning();
        return user;
      }
      async createLocalUser(email, password, firstName, lastName) {
        const [user] = await db.insert(users).values({
          email,
          password,
          firstName,
          lastName
        }).returning();
        return user;
      }
      // Restaurants
      async getAllRestaurants() {
        return await db.select().from(restaurants);
      }
      async getRestaurant(id) {
        const result = await db.select().from(restaurants).where(eq(restaurants.id, id)).limit(1);
        return result[0];
      }
      async createRestaurant(restaurant) {
        const result = await db.insert(restaurants).values(restaurant).returning();
        return result[0];
      }
      // Products
      async getProductsByRestaurant(restaurantId) {
        return await db.select().from(products).where(eq(products.restaurantId, restaurantId));
      }
      async getProduct(id) {
        const result = await db.select().from(products).where(eq(products.id, id)).limit(1);
        return result[0];
      }
      async createProduct(product) {
        const result = await db.insert(products).values(product).returning();
        return result[0];
      }
      // Orders
      async createOrder(order) {
        const result = await db.insert(orders).values(order).returning();
        return result[0];
      }
      async getOrder(id) {
        const result = await db.select().from(orders).where(eq(orders.id, id)).limit(1);
        return result[0];
      }
      async getOrdersByUser(userId) {
        return await db.select().from(orders).where(eq(orders.userId, userId)).orderBy(desc(orders.createdAt));
      }
      async updateOrderStatus(id, status) {
        const result = await db.update(orders).set({ status }).where(eq(orders.id, id)).returning();
        return result[0];
      }
      // Order Items
      async createOrderItem(orderItem) {
        const result = await db.insert(orderItems).values(orderItem).returning();
        return result[0];
      }
      async getOrderItems(orderId) {
        return await db.select().from(orderItems).where(eq(orderItems.orderId, orderId));
      }
      // User Points Management
      async addUserPoints(userId, points) {
        const result = await db.update(users).set({ points: sql2`${users.points} + ${points}` }).where(eq(users.id, userId)).returning();
        return result[0];
      }
      async subtractUserPoints(userId, points) {
        const result = await db.update(users).set({ points: sql2`${users.points} - ${points}` }).where(eq(users.id, userId)).returning();
        return result[0];
      }
      // Product Management (for admin)
      async updateProduct(id, product) {
        const result = await db.update(products).set(product).where(eq(products.id, id)).returning();
        return result[0];
      }
      async deleteProduct(id) {
        await db.delete(products).where(eq(products.id, id));
      }
      // Orders (for admin)
      async getAllOrders() {
        return await db.select().from(orders).orderBy(desc(orders.createdAt));
      }
      // Rewards
      async getAllRewards() {
        return await db.select().from(rewards);
      }
      async getActiveRewards() {
        return await db.select().from(rewards).where(eq(rewards.active, 1));
      }
      async getReward(id) {
        const result = await db.select().from(rewards).where(eq(rewards.id, id)).limit(1);
        return result[0];
      }
      async createReward(reward) {
        const result = await db.insert(rewards).values(reward).returning();
        return result[0];
      }
      async updateReward(id, reward) {
        const result = await db.update(rewards).set(reward).where(eq(rewards.id, id)).returning();
        return result[0];
      }
      // Reward Redemptions
      async createRedemption(redemption) {
        const result = await db.insert(rewardRedemptions).values(redemption).returning();
        return result[0];
      }
      async getUserRedemptions(userId) {
        return await db.select().from(rewardRedemptions).where(eq(rewardRedemptions.userId, userId)).orderBy(desc(rewardRedemptions.redeemedAt));
      }
      async getRedemption(id) {
        const result = await db.select().from(rewardRedemptions).where(eq(rewardRedemptions.id, id)).limit(1);
        return result[0];
      }
      async useRedemption(id) {
        const result = await db.update(rewardRedemptions).set({ status: "used", usedAt: /* @__PURE__ */ new Date() }).where(eq(rewardRedemptions.id, id)).returning();
        return result[0];
      }
    };
    storage = new DbStorage();
  }
});

// server/objectAcl.ts
var objectAcl_exports = {};
__export(objectAcl_exports, {
  ObjectAccessGroupType: () => ObjectAccessGroupType,
  ObjectPermission: () => ObjectPermission,
  canAccessObject: () => canAccessObject,
  getObjectAclPolicy: () => getObjectAclPolicy,
  setObjectAclPolicy: () => setObjectAclPolicy
});
function isPermissionAllowed(requested, granted) {
  if (requested === "read" /* READ */) {
    return ["read" /* READ */, "write" /* WRITE */].includes(granted);
  }
  return granted === "write" /* WRITE */;
}
function createObjectAccessGroup(group) {
  switch (group.type) {
    default:
      throw new Error(`Unknown access group type: ${group.type}`);
  }
}
async function setObjectAclPolicy(objectFile, aclPolicy) {
  const [exists] = await objectFile.exists();
  if (!exists) {
    throw new Error(`Object not found: ${objectFile.name}`);
  }
  await objectFile.setMetadata({
    metadata: {
      [ACL_POLICY_METADATA_KEY]: JSON.stringify(aclPolicy)
    }
  });
}
async function getObjectAclPolicy(objectFile) {
  const [metadata] = await objectFile.getMetadata();
  const aclPolicy = metadata?.metadata?.[ACL_POLICY_METADATA_KEY];
  if (!aclPolicy) {
    return null;
  }
  return JSON.parse(aclPolicy);
}
async function canAccessObject({
  userId,
  objectFile,
  requestedPermission
}) {
  const aclPolicy = await getObjectAclPolicy(objectFile);
  if (!aclPolicy) {
    return false;
  }
  if (aclPolicy.visibility === "public" && requestedPermission === "read" /* READ */) {
    return true;
  }
  if (!userId) {
    return false;
  }
  if (aclPolicy.owner === userId) {
    return true;
  }
  for (const rule of aclPolicy.aclRules || []) {
    const accessGroup = createObjectAccessGroup(rule.group);
    if (await accessGroup.hasMember(userId) && isPermissionAllowed(requestedPermission, rule.permission)) {
      return true;
    }
  }
  return false;
}
var ACL_POLICY_METADATA_KEY, ObjectAccessGroupType, ObjectPermission;
var init_objectAcl = __esm({
  "server/objectAcl.ts"() {
    "use strict";
    ACL_POLICY_METADATA_KEY = "custom:aclPolicy";
    ObjectAccessGroupType = /* @__PURE__ */ ((ObjectAccessGroupType2) => {
      return ObjectAccessGroupType2;
    })(ObjectAccessGroupType || {});
    ObjectPermission = /* @__PURE__ */ ((ObjectPermission2) => {
      ObjectPermission2["READ"] = "read";
      ObjectPermission2["WRITE"] = "write";
      return ObjectPermission2;
    })(ObjectPermission || {});
  }
});

// server/objectStorage.ts
var objectStorage_exports = {};
__export(objectStorage_exports, {
  ObjectNotFoundError: () => ObjectNotFoundError,
  ObjectStorageService: () => ObjectStorageService,
  objectStorageClient: () => objectStorageClient
});
import { Storage } from "@google-cloud/storage";
import { randomUUID } from "crypto";
function parseObjectPath(path3) {
  if (!path3.startsWith("/")) {
    path3 = `/${path3}`;
  }
  const pathParts = path3.split("/");
  if (pathParts.length < 3) {
    throw new Error("Invalid path: must contain at least a bucket name");
  }
  const bucketName = pathParts[1];
  const objectName = pathParts.slice(2).join("/");
  return {
    bucketName,
    objectName
  };
}
async function signObjectURL({
  bucketName,
  objectName,
  method,
  ttlSec
}) {
  const request = {
    bucket_name: bucketName,
    object_name: objectName,
    method,
    expires_at: new Date(Date.now() + ttlSec * 1e3).toISOString()
  };
  const response = await fetch(
    `${REPLIT_SIDECAR_ENDPOINT}/object-storage/signed-object-url`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(request)
    }
  );
  if (!response.ok) {
    throw new Error(
      `Failed to sign object URL, errorcode: ${response.status}, make sure you're running on Replit`
    );
  }
  const { signed_url: signedURL } = await response.json();
  return signedURL;
}
var REPLIT_SIDECAR_ENDPOINT, objectStorageClient, ObjectNotFoundError, ObjectStorageService;
var init_objectStorage = __esm({
  "server/objectStorage.ts"() {
    "use strict";
    init_objectAcl();
    REPLIT_SIDECAR_ENDPOINT = "http://127.0.0.1:1106";
    objectStorageClient = new Storage({
      credentials: {
        audience: "replit",
        subject_token_type: "access_token",
        token_url: `${REPLIT_SIDECAR_ENDPOINT}/token`,
        type: "external_account",
        credential_source: {
          url: `${REPLIT_SIDECAR_ENDPOINT}/credential`,
          format: {
            type: "json",
            subject_token_field_name: "access_token"
          }
        },
        universe_domain: "googleapis.com"
      },
      projectId: ""
    });
    ObjectNotFoundError = class _ObjectNotFoundError extends Error {
      constructor() {
        super("Object not found");
        this.name = "ObjectNotFoundError";
        Object.setPrototypeOf(this, _ObjectNotFoundError.prototype);
      }
    };
    ObjectStorageService = class {
      constructor() {
      }
      // Gets the public object search paths.
      getPublicObjectSearchPaths() {
        const pathsStr = process.env.PUBLIC_OBJECT_SEARCH_PATHS || "";
        const paths = Array.from(
          new Set(
            pathsStr.split(",").map((path3) => path3.trim()).filter((path3) => path3.length > 0)
          )
        );
        if (paths.length === 0) {
          throw new Error(
            "PUBLIC_OBJECT_SEARCH_PATHS not set. Create a bucket in 'Object Storage' tool and set PUBLIC_OBJECT_SEARCH_PATHS env var (comma-separated paths)."
          );
        }
        return paths;
      }
      // Gets the private object directory.
      getPrivateObjectDir() {
        const dir = process.env.PRIVATE_OBJECT_DIR || "";
        if (!dir) {
          throw new Error(
            "PRIVATE_OBJECT_DIR not set. Create a bucket in 'Object Storage' tool and set PRIVATE_OBJECT_DIR env var."
          );
        }
        return dir;
      }
      // Search for a public object from the search paths.
      async searchPublicObject(filePath) {
        for (const searchPath of this.getPublicObjectSearchPaths()) {
          const fullPath = `${searchPath}/${filePath}`;
          const { bucketName, objectName } = parseObjectPath(fullPath);
          const bucket = objectStorageClient.bucket(bucketName);
          const file = bucket.file(objectName);
          const [exists] = await file.exists();
          if (exists) {
            return file;
          }
        }
        return null;
      }
      // Downloads an object to the response.
      async downloadObject(file, res, cacheTtlSec = 3600) {
        try {
          const [metadata] = await file.getMetadata();
          const aclPolicy = await getObjectAclPolicy(file);
          const isPublic = aclPolicy?.visibility === "public";
          res.set({
            "Content-Type": metadata.contentType || "application/octet-stream",
            "Content-Length": metadata.size,
            "Cache-Control": `${isPublic ? "public" : "private"}, max-age=${cacheTtlSec}`
          });
          const stream = file.createReadStream();
          stream.on("error", (err) => {
            console.error("Stream error:", err);
            if (!res.headersSent) {
              res.status(500).json({ error: "Error streaming file" });
            }
          });
          stream.pipe(res);
        } catch (error) {
          console.error("Error downloading file:", error);
          if (!res.headersSent) {
            res.status(500).json({ error: "Error downloading file" });
          }
        }
      }
      // Gets the upload URL for an object entity.
      async getObjectEntityUploadURL() {
        const privateObjectDir = this.getPrivateObjectDir();
        if (!privateObjectDir) {
          throw new Error(
            "PRIVATE_OBJECT_DIR not set. Create a bucket in 'Object Storage' tool and set PRIVATE_OBJECT_DIR env var."
          );
        }
        const objectId = randomUUID();
        const fullPath = `${privateObjectDir}/uploads/${objectId}`;
        const { bucketName, objectName } = parseObjectPath(fullPath);
        return signObjectURL({
          bucketName,
          objectName,
          method: "PUT",
          ttlSec: 900
        });
      }
      // Gets the object entity file from the object path.
      async getObjectEntityFile(objectPath) {
        if (!objectPath.startsWith("/objects/")) {
          throw new ObjectNotFoundError();
        }
        const parts = objectPath.slice(1).split("/");
        if (parts.length < 2) {
          throw new ObjectNotFoundError();
        }
        const entityId = parts.slice(1).join("/");
        let entityDir = this.getPrivateObjectDir();
        if (!entityDir.endsWith("/")) {
          entityDir = `${entityDir}/`;
        }
        const objectEntityPath = `${entityDir}${entityId}`;
        const { bucketName, objectName } = parseObjectPath(objectEntityPath);
        const bucket = objectStorageClient.bucket(bucketName);
        const objectFile = bucket.file(objectName);
        const [exists] = await objectFile.exists();
        if (!exists) {
          throw new ObjectNotFoundError();
        }
        return objectFile;
      }
      normalizeObjectEntityPath(rawPath) {
        if (!rawPath.startsWith("https://storage.googleapis.com/")) {
          return rawPath;
        }
        const url = new URL(rawPath);
        const rawObjectPath = url.pathname;
        let objectEntityDir = this.getPrivateObjectDir();
        if (!objectEntityDir.endsWith("/")) {
          objectEntityDir = `${objectEntityDir}/`;
        }
        if (!rawObjectPath.startsWith(objectEntityDir)) {
          return rawObjectPath;
        }
        const entityId = rawObjectPath.slice(objectEntityDir.length);
        return `/objects/${entityId}`;
      }
      // Tries to set the ACL policy for the object entity and return the normalized path.
      async trySetObjectEntityAclPolicy(rawPath, aclPolicy) {
        const normalizedPath = this.normalizeObjectEntityPath(rawPath);
        if (!normalizedPath.startsWith("/")) {
          return normalizedPath;
        }
        const objectFile = await this.getObjectEntityFile(normalizedPath);
        await setObjectAclPolicy(objectFile, aclPolicy);
        return normalizedPath;
      }
      // Checks if the user can access the object entity.
      async canAccessObjectEntity({
        userId,
        objectFile,
        requestedPermission
      }) {
        return canAccessObject({
          userId,
          objectFile,
          requestedPermission: requestedPermission ?? "read" /* READ */
        });
      }
    };
  }
});

// server/websocket.ts
var websocket_exports = {};
__export(websocket_exports, {
  notifyNewOrder: () => notifyNewOrder,
  notifyOrderStatusUpdate: () => notifyOrderStatusUpdate,
  setupWebSocket: () => setupWebSocket
});
import { WebSocketServer, WebSocket } from "ws";
import { parse as parseCookie } from "cookie";
import session2 from "express-session";
import connectPg2 from "connect-pg-simple";
function getSessionId(req) {
  try {
    const cookies = req.headers.cookie ? parseCookie(req.headers.cookie) : {};
    const sessionCookie = cookies["connect.sid"];
    if (!sessionCookie) return null;
    const match = sessionCookie.match(/^s:([^.]+)\./);
    return match ? match[1] : null;
  } catch (error) {
    console.error("Error extracting session ID:", error);
    return null;
  }
}
async function verifyAdmin(sessionId) {
  return new Promise((resolve) => {
    sessionStore.get(sessionId, async (err, session3) => {
      if (err || !session3) {
        console.log("Session not found or error:", err);
        return resolve({ isAdmin: false });
      }
      try {
        const passport3 = session3.passport;
        if (!passport3 || !passport3.user) {
          return resolve({ isAdmin: false });
        }
        const user = passport3.user;
        const userId = user.claims ? user.claims.sub : user.id;
        if (!userId) {
          return resolve({ isAdmin: false });
        }
        const { storage: storage2 } = await Promise.resolve().then(() => (init_storage(), storage_exports));
        const dbUser = await storage2.getUser(userId);
        if (dbUser && dbUser.isAdmin === 1) {
          return resolve({ isAdmin: true, userId });
        }
        return resolve({ isAdmin: false });
      } catch (error) {
        console.error("Error verifying admin:", error);
        return resolve({ isAdmin: false });
      }
    });
  });
}
function setupWebSocket(server) {
  wss = new WebSocketServer({
    server,
    path: "/ws",
    verifyClient: async ({ req }, callback) => {
      const sessionId = getSessionId(req);
      if (!sessionId) {
        console.log("WebSocket connection rejected: No session");
        return callback(false, 401, "Unauthorized");
      }
      const { isAdmin: isAdmin2, userId } = await verifyAdmin(sessionId);
      if (!isAdmin2) {
        console.log("WebSocket connection rejected: Not admin");
        return callback(false, 403, "Forbidden");
      }
      req.userId = userId;
      callback(true);
    }
  });
  wss.on("connection", (ws2, req) => {
    const userId = req.userId;
    console.log(`WebSocket admin client connected: ${userId}`);
    ws2.on("message", (message) => {
      try {
        const data = JSON.parse(message.toString());
        if (data.type === "register_admin") {
          adminClients.set(ws2, userId);
          console.log(`Admin client ${userId} registered for notifications`);
        }
      } catch (error) {
        console.error("Error parsing WebSocket message:", error);
      }
    });
    ws2.on("close", () => {
      adminClients.delete(ws2);
      console.log(`WebSocket admin client disconnected: ${userId}`);
    });
    ws2.on("error", (error) => {
      console.error("WebSocket error:", error);
      adminClients.delete(ws2);
    });
  });
  console.log("WebSocket server initialized");
}
function notifyNewOrder(order) {
  if (!wss) return;
  const message = JSON.stringify({
    type: "new_order",
    order,
    timestamp: (/* @__PURE__ */ new Date()).toISOString()
  });
  let sentCount = 0;
  adminClients.forEach((userId, client2) => {
    if (client2.readyState === WebSocket.OPEN) {
      client2.send(message);
      sentCount++;
    }
  });
  console.log(`New order notification sent to ${sentCount} admin client(s)`);
}
function notifyOrderStatusUpdate(orderId, newStatus) {
  if (!wss) return;
  const message = JSON.stringify({
    type: "order_status_update",
    orderId,
    newStatus,
    timestamp: (/* @__PURE__ */ new Date()).toISOString()
  });
  adminClients.forEach((userId, client2) => {
    if (client2.readyState === WebSocket.OPEN) {
      client2.send(message);
    }
  });
  console.log(`Order status update notification sent for order ${orderId}`);
}
var wss, adminClients, pgStore, sessionStore;
var init_websocket = __esm({
  "server/websocket.ts"() {
    "use strict";
    wss = null;
    adminClients = /* @__PURE__ */ new Map();
    pgStore = connectPg2(session2);
    sessionStore = new pgStore({
      conString: process.env.DATABASE_URL,
      createTableIfMissing: false,
      ttl: 7 * 24 * 60 * 60 * 1e3,
      tableName: "sessions"
    });
  }
});

// server/seed.ts
var seed_exports = {};
__export(seed_exports, {
  seedDatabase: () => seedDatabase
});
async function seedDatabase() {
  console.log("Seeding database...");
  const existingRestaurants = await storage.getAllRestaurants();
  if (existingRestaurants.length > 0) {
    console.log("Database already seeded, skipping...");
    return;
  }
  const store = await storage.createRestaurant({
    name: "Tienda de Pollo, El Cl\xE1sico",
    image: STORE_IMAGE,
    rating: "4.9",
    reviewCount: 1250,
    deliveryTime: "20-30 min",
    deliveryFee: 0,
    minOrder: 100,
    categories: ["Pollo", "Almac\xE9n", "Bebidas", "Congelados", "Preparados"],
    promotion: "Env\xEDo gratis"
  });
  console.log(`Created store: ${store.name}`);
  const products2 = [
    // Pollo
    {
      name: "Pollo Entero",
      description: "Pollo fresco entero, listo para preparar",
      price: 180,
      image: PRODUCT_IMAGES.pollo,
      category: "Pollo"
    },
    {
      name: "Pechuga de Pollo",
      description: "Pechuga de pollo sin hueso, 500g",
      price: 120,
      image: PRODUCT_IMAGES.pollo,
      category: "Pollo"
    },
    {
      name: "Alitas de Pollo",
      description: "Alitas de pollo frescas, 1kg",
      price: 95,
      image: PRODUCT_IMAGES.pollo,
      category: "Pollo"
    },
    {
      name: "Muslos de Pollo",
      description: "Muslos de pollo frescos, 1kg",
      price: 85,
      image: PRODUCT_IMAGES.pollo,
      category: "Pollo"
    },
    // Almacén
    {
      name: "Arroz Blanco",
      description: "Arroz blanco de grano largo, 1kg",
      price: 45,
      image: PRODUCT_IMAGES.arroz,
      category: "Almac\xE9n"
    },
    {
      name: "Frijoles Negros",
      description: "Frijoles negros secos, 500g",
      price: 35,
      image: PRODUCT_IMAGES.frijoles,
      category: "Almac\xE9n"
    },
    {
      name: "Aceite Vegetal",
      description: "Aceite vegetal, 1 litro",
      price: 55,
      image: PRODUCT_IMAGES.aceite,
      category: "Almac\xE9n"
    },
    {
      name: "Pasta Espagueti",
      description: "Pasta espagueti, 500g",
      price: 40,
      image: PRODUCT_IMAGES.pasta,
      category: "Almac\xE9n"
    },
    {
      name: "Salsa de Tomate",
      description: "Salsa de tomate concentrada, 400g",
      price: 30,
      image: PRODUCT_IMAGES.salsa,
      category: "Almac\xE9n"
    },
    {
      name: "Pan de Molde",
      description: "Pan de molde blanco, 500g",
      price: 38,
      image: PRODUCT_IMAGES.pan,
      category: "Almac\xE9n"
    },
    // Bebidas
    {
      name: "Coca-Cola",
      description: "Coca-Cola 2 litros",
      price: 60,
      image: PRODUCT_IMAGES.coca,
      category: "Bebidas"
    },
    {
      name: "Agua Mineral",
      description: "Agua mineral sin gas, 1.5 litros",
      price: 25,
      image: PRODUCT_IMAGES.agua,
      category: "Bebidas"
    },
    {
      name: "Cerveza",
      description: "Cerveza lager, pack 6 unidades",
      price: 110,
      image: PRODUCT_IMAGES.cerveza,
      category: "Bebidas"
    },
    {
      name: "Jugo de Naranja",
      description: "Jugo de naranja natural, 1 litro",
      price: 50,
      image: PRODUCT_IMAGES.jugo,
      category: "Bebidas"
    },
    // Congelados
    {
      name: "Pizza Congelada",
      description: "Pizza margarita congelada, lista para hornear",
      price: 95,
      image: PRODUCT_IMAGES.pizza,
      category: "Congelados"
    },
    {
      name: "Helado de Vainilla",
      description: "Helado de vainilla, 1 litro",
      price: 85,
      image: PRODUCT_IMAGES.helado,
      category: "Congelados"
    },
    {
      name: "Verduras Mixtas",
      description: "Mezcla de verduras congeladas, 500g",
      price: 45,
      image: PRODUCT_IMAGES.verduras,
      category: "Congelados"
    },
    {
      name: "Papas Fritas Congeladas",
      description: "Papas fritas precocidas congeladas, 1kg",
      price: 65,
      image: PRODUCT_IMAGES.papas,
      category: "Congelados"
    },
    // Preparados
    {
      name: "Pollo Asado",
      description: "Pollo entero asado, listo para comer",
      price: 220,
      image: PRODUCT_IMAGES.pollo,
      category: "Preparados"
    },
    {
      name: "Ensalada C\xE9sar",
      description: "Ensalada c\xE9sar fresca preparada",
      price: 75,
      image: PRODUCT_IMAGES.verduras,
      category: "Preparados"
    },
    {
      name: "Huevos Cocidos",
      description: "Pack de 6 huevos cocidos",
      price: 45,
      image: PRODUCT_IMAGES.huevos,
      category: "Preparados"
    }
  ];
  for (const product of products2) {
    await storage.createProduct({
      restaurantId: store.id,
      ...product
    });
  }
  console.log(`Created ${products2.length} products for ${store.name}`);
  const rewardsData = [
    {
      name: "$50 de descuento",
      description: "Cup\xF3n de $50 de descuento en tu pr\xF3xima compra",
      pointsCost: 500,
      image: "https://images.unsplash.com/photo-1607082348824-0a96f2a4b9da?w=400&auto=format&fit=crop",
      type: "discount",
      value: 50,
      stock: -1,
      active: 1
    },
    {
      name: "$100 de descuento",
      description: "Cup\xF3n de $100 de descuento en tu pr\xF3xima compra",
      pointsCost: 1e3,
      image: "https://images.unsplash.com/photo-1607082349566-187342175e2f?w=400&auto=format&fit=crop",
      type: "discount",
      value: 100,
      stock: -1,
      active: 1
    },
    {
      name: "Pollo Entero Gratis",
      description: "Pollo entero fresco completamente gratis",
      pointsCost: 1800,
      image: PRODUCT_IMAGES.pollo,
      type: "product",
      value: 180,
      stock: -1,
      active: 1
    },
    {
      name: "Combo Bebidas",
      description: "Pack de 2 Coca-Colas de 2L gratis",
      pointsCost: 600,
      image: PRODUCT_IMAGES.coca,
      type: "product",
      value: 120,
      stock: 50,
      active: 1
    },
    {
      name: "$200 de descuento",
      description: "Cup\xF3n de $200 de descuento en compras mayores a $500",
      pointsCost: 2e3,
      image: "https://images.unsplash.com/photo-1607082350899-7e105aa886ae?w=400&auto=format&fit=crop",
      type: "discount",
      value: 200,
      stock: -1,
      active: 1
    }
  ];
  for (const reward of rewardsData) {
    await storage.createReward(reward);
  }
  console.log(`Created ${rewardsData.length} rewards`);
  console.log("Database seeding complete!");
}
var STORE_IMAGE, PRODUCT_IMAGES;
var init_seed = __esm({
  "server/seed.ts"() {
    "use strict";
    init_storage();
    STORE_IMAGE = "https://images.unsplash.com/photo-1604719312566-8912e9227c6a?w=800&auto=format&fit=crop";
    PRODUCT_IMAGES = {
      pollo: "https://images.unsplash.com/photo-1598103442097-8b74394b95c6?w=400&auto=format&fit=crop",
      arroz: "https://images.unsplash.com/photo-1586201375761-83865001e31c?w=400&auto=format&fit=crop",
      frijoles: "https://images.unsplash.com/photo-1596797038530-2c107229654b?w=400&auto=format&fit=crop",
      aceite: "https://images.unsplash.com/photo-1474979266404-7eaacbcd87c5?w=400&auto=format&fit=crop",
      pasta: "https://images.unsplash.com/photo-1621996346565-e3dbc646d9a9?w=400&auto=format&fit=crop",
      coca: "https://images.unsplash.com/photo-1554866585-cd94860890b7?w=400&auto=format&fit=crop",
      agua: "https://images.unsplash.com/photo-1548839140-29a749e1cf4d?w=400&auto=format&fit=crop",
      cerveza: "https://images.unsplash.com/photo-1608270586620-248524c67de9?w=400&auto=format&fit=crop",
      jugo: "https://images.unsplash.com/photo-1600271886742-f049cd451bba?w=400&auto=format&fit=crop",
      pizza: "https://images.unsplash.com/photo-1565299624946-b28f40a0ae38?w=400&auto=format&fit=crop",
      helado: "https://images.unsplash.com/photo-1563805042-7684c019e1cb?w=400&auto=format&fit=crop",
      verduras: "https://images.unsplash.com/photo-1597362925123-77861d3fbac7?w=400&auto=format&fit=crop",
      papas: "https://images.unsplash.com/photo-1573080496219-bb080dd4f877?w=400&auto=format&fit=crop",
      salsa: "https://images.unsplash.com/photo-1472476443507-c7a5948772fc?w=400&auto=format&fit=crop",
      pan: "https://images.unsplash.com/photo-1509440159596-0249088772ff?w=400&auto=format&fit=crop",
      huevos: "https://images.unsplash.com/photo-1582722872445-44dc5f7e3c8f?w=400&auto=format&fit=crop"
    };
  }
});

// server/index.ts
import express2 from "express";

// server/routes.ts
init_storage();
init_schema();
import { createServer } from "http";
import { z as z2 } from "zod";

// server/replitAuth.ts
init_storage();
import * as client from "openid-client";
import { Strategy } from "openid-client/passport";
import passport from "passport";
import session from "express-session";
import memoize from "memoizee";
import connectPg from "connect-pg-simple";
if (!process.env.REPLIT_DOMAINS) {
  throw new Error("Environment variable REPLIT_DOMAINS not provided");
}
var getOidcConfig = memoize(
  async () => {
    return await client.discovery(
      new URL(process.env.ISSUER_URL ?? "https://replit.com/oidc"),
      process.env.REPL_ID
    );
  },
  { maxAge: 3600 * 1e3 }
);
function getSession() {
  const sessionTtl = 7 * 24 * 60 * 60 * 1e3;
  const pgStore2 = connectPg(session);
  const sessionStore2 = new pgStore2({
    conString: process.env.DATABASE_URL,
    createTableIfMissing: false,
    ttl: sessionTtl,
    tableName: "sessions"
  });
  return session({
    secret: process.env.SESSION_SECRET,
    store: sessionStore2,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: true,
      maxAge: sessionTtl
    }
  });
}
function updateUserSession(user, tokens) {
  user.claims = tokens.claims();
  user.access_token = tokens.access_token;
  user.refresh_token = tokens.refresh_token;
  user.expires_at = user.claims?.exp;
}
async function upsertUser(claims) {
  await storage.upsertUser({
    id: claims["sub"],
    email: claims["email"],
    firstName: claims["first_name"],
    lastName: claims["last_name"],
    profileImageUrl: claims["profile_image_url"]
  });
}
async function setupAuth(app2) {
  app2.set("trust proxy", 1);
  app2.use(getSession());
  app2.use(passport.initialize());
  app2.use(passport.session());
  const config = await getOidcConfig();
  const verify = async (tokens, verified) => {
    const user = {};
    updateUserSession(user, tokens);
    await upsertUser(tokens.claims());
    verified(null, user);
  };
  for (const domain of process.env.REPLIT_DOMAINS.split(",")) {
    const strategy = new Strategy(
      {
        name: `replitauth:${domain}`,
        config,
        scope: "openid email profile offline_access",
        callbackURL: `https://${domain}/api/callback`
      },
      verify
    );
    passport.use(strategy);
  }
  passport.serializeUser((user, cb) => cb(null, user));
  passport.deserializeUser((user, cb) => cb(null, user));
  app2.get("/api/login", (req, res, next) => {
    passport.authenticate(`replitauth:${req.hostname}`, {
      prompt: "login consent",
      scope: ["openid", "email", "profile", "offline_access"]
    })(req, res, next);
  });
  app2.get("/api/callback", (req, res, next) => {
    passport.authenticate(`replitauth:${req.hostname}`, {
      successReturnToOrRedirect: "/",
      failureRedirect: "/api/login"
    })(req, res, next);
  });
  app2.get("/api/logout", (req, res) => {
    req.logout(() => {
      res.redirect(
        client.buildEndSessionUrl(config, {
          client_id: process.env.REPL_ID,
          post_logout_redirect_uri: `${req.protocol}://${req.hostname}`
        }).href
      );
    });
  });
}
var isAuthenticated = async (req, res, next) => {
  const user = req.user;
  if (!req.isAuthenticated()) {
    return res.status(401).json({ message: "Unauthorized" });
  }
  if (user.id && !user.expires_at) {
    return next();
  }
  if (!user.expires_at) {
    return res.status(401).json({ message: "Unauthorized" });
  }
  const now = Math.floor(Date.now() / 1e3);
  if (now <= user.expires_at) {
    return next();
  }
  const refreshToken = user.refresh_token;
  if (!refreshToken) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }
  try {
    const config = await getOidcConfig();
    const tokenResponse = await client.refreshTokenGrant(config, refreshToken);
    updateUserSession(user, tokenResponse);
    return next();
  } catch (error) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }
};

// server/localAuth.ts
import passport2 from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import bcrypt from "bcryptjs";
import { z } from "zod";
var registerSchema = z.object({
  email: z.string().email("Email inv\xE1lido"),
  password: z.string().min(6, "La contrase\xF1a debe tener al menos 6 caracteres"),
  firstName: z.string().optional(),
  lastName: z.string().optional()
});
var loginSchema = z.object({
  email: z.string().email("Email inv\xE1lido"),
  password: z.string().min(1, "La contrase\xF1a es requerida")
});
function setupLocalAuth(app2, storage2) {
  passport2.use(
    new LocalStrategy(
      {
        usernameField: "email",
        passwordField: "password"
      },
      async (email, password, done) => {
        try {
          const user = await storage2.getUserByEmail(email);
          if (!user || !user.password) {
            return done(null, false, { message: "Email o contrase\xF1a incorrectos" });
          }
          const isValidPassword = await bcrypt.compare(password, user.password);
          if (!isValidPassword) {
            return done(null, false, { message: "Email o contrase\xF1a incorrectos" });
          }
          const { password: _, ...userWithoutPassword } = user;
          return done(null, { id: user.id });
        } catch (error) {
          return done(error);
        }
      }
    )
  );
  app2.post("/api/register", async (req, res) => {
    try {
      const validationResult = registerSchema.safeParse(req.body);
      if (!validationResult.success) {
        const errors = validationResult.error.errors.map((err) => err.message).join(", ");
        return res.status(400).json({ message: errors });
      }
      const { email, password, firstName, lastName } = validationResult.data;
      const existingUser = await storage2.getUserByEmail(email);
      if (existingUser) {
        return res.status(400).json({ message: "Este email ya est\xE1 registrado" });
      }
      const hashedPassword = await bcrypt.hash(password, 10);
      const user = await storage2.createLocalUser(
        email,
        hashedPassword,
        firstName,
        lastName
      );
      req.login({ id: user.id }, (err) => {
        if (err) {
          return res.status(500).json({ message: "Error al iniciar sesi\xF3n" });
        }
        const { password: _, ...userWithoutPassword } = user;
        res.json(userWithoutPassword);
      });
    } catch (error) {
      console.error("Error en registro:", error);
      res.status(500).json({ message: "Error al crear usuario" });
    }
  });
  app2.post("/api/local-login", (req, res, next) => {
    const validationResult = loginSchema.safeParse(req.body);
    if (!validationResult.success) {
      const errors = validationResult.error.errors.map((err) => err.message).join(", ");
      return res.status(400).json({ message: errors });
    }
    passport2.authenticate("local", async (err, user, info) => {
      if (err) {
        return res.status(500).json({ message: "Error en el servidor" });
      }
      if (!user) {
        return res.status(401).json({ message: info?.message || "Credenciales incorrectas" });
      }
      req.login(user, async (loginErr) => {
        if (loginErr) {
          return res.status(500).json({ message: "Error al iniciar sesi\xF3n" });
        }
        try {
          const fullUser = await storage2.getUser(user.id);
          if (!fullUser) {
            return res.status(404).json({ message: "Usuario no encontrado" });
          }
          const { password: _, ...userWithoutPassword } = fullUser;
          return res.json(userWithoutPassword);
        } catch (error) {
          return res.status(500).json({ message: "Error al obtener usuario" });
        }
      });
    })(req, res, next);
  });
  app2.post("/api/logout", (req, res) => {
    req.logout((err) => {
      if (err) {
        return res.status(500).json({ message: "Error al cerrar sesi\xF3n" });
      }
      res.json({ message: "Sesi\xF3n cerrada exitosamente" });
    });
  });
}

// server/routes.ts
import { MercadoPagoConfig, Preference } from "mercadopago";
var isAdmin = async (req, res, next) => {
  try {
    if (!req.isAuthenticated()) {
      return res.status(401).json({ message: "No autenticado" });
    }
    const userId = req.user.claims ? req.user.claims.sub : req.user.id;
    const user = await storage.getUser(userId);
    if (!user || !user.isAdmin) {
      return res.status(403).json({ message: "Acceso denegado - se requieren permisos de administrador" });
    }
    next();
  } catch (error) {
    console.error("Error in isAdmin middleware:", error);
    res.status(500).json({ message: "Error de autenticaci\xF3n" });
  }
};
var mercadoPagoClient = process.env.MERCADOPAGO_ACCESS_TOKEN ? new MercadoPagoConfig({ accessToken: process.env.MERCADOPAGO_ACCESS_TOKEN }) : null;
async function registerRoutes(app2) {
  await setupAuth(app2);
  setupLocalAuth(app2, storage);
  app2.post("/api/create-preference", async (req, res) => {
    console.log("=== CREATE PREFERENCE REQUEST ===");
    console.log("Request body:", JSON.stringify(req.body, null, 2));
    try {
      if (!mercadoPagoClient) {
        console.log("ERROR: Mercado Pago client not configured");
        return res.status(400).json({ message: "Mercado Pago no configurado" });
      }
      if (!req.isAuthenticated()) {
        console.log("ERROR: User not authenticated");
        return res.status(401).json({ message: "Usuario no autenticado" });
      }
      const userId = req.user.claims ? req.user.claims.sub : req.user.id;
      console.log("User ID:", userId);
      const user = await storage.getUser(userId);
      if (!user) {
        console.log("ERROR: User not found in database");
        return res.status(404).json({ message: "Usuario no encontrado" });
      }
      console.log("User found:", user.email);
      const { items, orderId } = req.body;
      console.log("Order ID received:", orderId);
      if (!items || !Array.isArray(items) || items.length === 0) {
        return res.status(400).json({ message: "Items inv\xE1lidos" });
      }
      const preference = new Preference(mercadoPagoClient);
      const baseUrl = process.env.REPLIT_DEV_DOMAIN ? `https://${process.env.REPLIT_DEV_DOMAIN}` : "http://localhost:5000";
      const result = await preference.create({
        body: {
          items: items.map((item) => ({
            id: item.id,
            title: item.title,
            quantity: item.quantity,
            unit_price: item.unit_price,
            currency_id: "ARS"
          })),
          payer: {
            name: user.firstName || "",
            surname: user.lastName || "",
            email: user.email || ""
          },
          back_urls: {
            success: `${baseUrl}/order-confirmation/${orderId}`,
            failure: `${baseUrl}/checkout`,
            pending: `${baseUrl}/order-confirmation/${orderId}`
          },
          auto_return: "approved",
          external_reference: orderId || ""
        }
      });
      console.log("MercadoPago result:", JSON.stringify(result, null, 2));
      res.json({ preferenceId: result.id, initPoint: result.init_point });
    } catch (error) {
      console.error("Error creating preference:", error);
      res.status(500).json({ message: "Error al crear preferencia de pago: " + error.message });
    }
  });
  app2.get("/api/auth/user", async (req, res) => {
    try {
      if (!req.isAuthenticated()) {
        return res.status(401).json({ message: "No autenticado" });
      }
      const userId = req.user.claims ? req.user.claims.sub : req.user.id;
      const user = await storage.getUser(userId);
      if (!user) {
        return res.status(404).json({ message: "Usuario no encontrado" });
      }
      const { password: _, ...userWithoutPassword } = user;
      res.json(userWithoutPassword);
    } catch (error) {
      console.error("Error fetching user:", error);
      res.status(500).json({ message: "Failed to fetch user" });
    }
  });
  app2.post("/api/auth/logout", (req, res) => {
    console.log("=== LOGOUT REQUEST ===");
    console.log("Authenticated:", req.isAuthenticated());
    console.log("User:", req.user);
    req.logout((err) => {
      if (err) {
        console.error("Error logging out:", err);
        return res.status(500).json({ message: "Error al cerrar sesi\xF3n" });
      }
      console.log("Passport logout successful, destroying session...");
      req.session.destroy((err2) => {
        if (err2) {
          console.error("Error destroying session:", err2);
          res.clearCookie("connect.sid");
          return res.json({ message: "Sesi\xF3n cerrada exitosamente" });
        }
        console.log("Session destroyed successfully");
        res.clearCookie("connect.sid");
        res.json({ message: "Sesi\xF3n cerrada exitosamente" });
      });
    });
  });
  const {
    ObjectStorageService: ObjectStorageService2,
    ObjectNotFoundError: ObjectNotFoundError2
  } = await Promise.resolve().then(() => (init_objectStorage(), objectStorage_exports));
  const { ObjectPermission: ObjectPermission2 } = await Promise.resolve().then(() => (init_objectAcl(), objectAcl_exports));
  app2.get("/objects/:objectPath(*)", async (req, res) => {
    const objectStorageService = new ObjectStorageService2();
    try {
      const objectFile = await objectStorageService.getObjectEntityFile(
        req.path
      );
      objectStorageService.downloadObject(objectFile, res);
    } catch (error) {
      console.error("Error checking object access:", error);
      if (error instanceof ObjectNotFoundError2) {
        return res.sendStatus(404);
      }
      return res.sendStatus(500);
    }
  });
  app2.post("/api/objects/upload", isAdmin, async (req, res) => {
    const objectStorageService = new ObjectStorageService2();
    try {
      const uploadURL = await objectStorageService.getObjectEntityUploadURL();
      res.json({ uploadURL });
    } catch (error) {
      console.error("Error getting upload URL:", error);
      res.status(500).json({ error: "Failed to get upload URL" });
    }
  });
  app2.put("/api/product-images", isAdmin, async (req, res) => {
    if (!req.body.productImageURL) {
      return res.status(400).json({ error: "productImageURL is required" });
    }
    const userId = req.user.claims ? req.user.claims.sub : req.user.id;
    try {
      const objectStorageService = new ObjectStorageService2();
      const objectPath = await objectStorageService.trySetObjectEntityAclPolicy(
        req.body.productImageURL,
        {
          owner: userId,
          visibility: "public"
          // Product images are public
        }
      );
      res.status(200).json({
        objectPath
      });
    } catch (error) {
      console.error("Error setting product image:", error);
      res.status(500).json({ error: "Internal server error" });
    }
  });
  app2.get("/api/restaurants", async (_req, res) => {
    try {
      const restaurants2 = await storage.getAllRestaurants();
      res.json(restaurants2);
    } catch (error) {
      console.error("Error fetching restaurants:", error);
      res.status(500).json({ error: "Failed to fetch restaurants" });
    }
  });
  app2.get("/api/restaurants/:id", async (req, res) => {
    try {
      const restaurant = await storage.getRestaurant(req.params.id);
      if (!restaurant) {
        return res.status(404).json({ error: "Restaurant not found" });
      }
      res.json(restaurant);
    } catch (error) {
      console.error("Error fetching restaurant:", error);
      res.status(500).json({ error: "Failed to fetch restaurant" });
    }
  });
  app2.get("/api/restaurants/:id/products", async (req, res) => {
    try {
      const products2 = await storage.getProductsByRestaurant(req.params.id);
      res.json(products2);
    } catch (error) {
      console.error("Error fetching products:", error);
      res.status(500).json({ error: "Failed to fetch products" });
    }
  });
  app2.post("/api/orders", isAuthenticated, async (req, res) => {
    console.log("=== CREATE ORDER REQUEST ===");
    console.log("Request body:", JSON.stringify(req.body, null, 2));
    try {
      const userId = req.user.claims ? req.user.claims.sub : req.user.id;
      console.log("User ID:", userId);
      const orderSchema = insertOrderSchema.extend({
        items: z2.array(
          z2.object({
            productId: z2.string(),
            productName: z2.string(),
            productPrice: z2.number(),
            productImage: z2.string(),
            quantity: z2.number()
          })
        )
      });
      const validated = orderSchema.parse(req.body);
      const order = await storage.createOrder({
        userId,
        ...validated
      });
      for (const item of validated.items) {
        await storage.createOrderItem({
          orderId: order.id,
          productId: item.productId,
          productName: item.productName,
          productPrice: item.productPrice,
          productImage: item.productImage,
          quantity: item.quantity
        });
      }
      await storage.addUserPoints(userId, validated.total);
      const { notifyNewOrder: notifyNewOrder2 } = await Promise.resolve().then(() => (init_websocket(), websocket_exports));
      notifyNewOrder2(order);
      res.status(201).json(order);
    } catch (error) {
      if (error instanceof z2.ZodError) {
        return res.status(400).json({ error: error.errors });
      }
      console.error("Error creating order:", error);
      res.status(500).json({ error: "Failed to create order" });
    }
  });
  app2.get("/api/orders", isAuthenticated, async (req, res) => {
    try {
      const userId = req.user.claims ? req.user.claims.sub : req.user.id;
      const orders2 = await storage.getOrdersByUser(userId);
      res.json(orders2);
    } catch (error) {
      console.error("Error fetching orders:", error);
      res.status(500).json({ error: "Failed to fetch orders" });
    }
  });
  app2.get("/api/orders/:id", isAuthenticated, async (req, res) => {
    try {
      const userId = req.user.claims ? req.user.claims.sub : req.user.id;
      const order = await storage.getOrder(req.params.id);
      if (!order) {
        return res.status(404).json({ error: "Order not found" });
      }
      if (order.userId !== userId) {
        return res.status(403).json({ error: "Forbidden" });
      }
      res.json(order);
    } catch (error) {
      console.error("Error fetching order:", error);
      res.status(500).json({ error: "Failed to fetch order" });
    }
  });
  app2.get("/api/orders/:id/items", isAuthenticated, async (req, res) => {
    try {
      const userId = req.user.claims ? req.user.claims.sub : req.user.id;
      const order = await storage.getOrder(req.params.id);
      if (!order) {
        return res.status(404).json({ error: "Order not found" });
      }
      if (order.userId !== userId) {
        return res.status(403).json({ error: "Forbidden" });
      }
      const items = await storage.getOrderItems(req.params.id);
      res.json(items);
    } catch (error) {
      console.error("Error fetching order items:", error);
      res.status(500).json({ error: "Failed to fetch order items" });
    }
  });
  app2.patch("/api/orders/:id/status", isAuthenticated, async (req, res) => {
    try {
      const { status } = req.body;
      if (!status || typeof status !== "string") {
        return res.status(400).json({ error: "Invalid status" });
      }
      const order = await storage.updateOrderStatus(req.params.id, status);
      if (!order) {
        return res.status(404).json({ error: "Order not found" });
      }
      res.json(order);
    } catch (error) {
      console.error("Error updating order status:", error);
      res.status(500).json({ error: "Failed to update order status" });
    }
  });
  app2.get("/api/orders/:id/restaurant", isAuthenticated, async (req, res) => {
    try {
      const userId = req.user.claims ? req.user.claims.sub : req.user.id;
      const order = await storage.getOrder(req.params.id);
      if (!order) {
        return res.status(404).json({ error: "Order not found" });
      }
      if (order.userId !== userId) {
        return res.status(403).json({ error: "Forbidden" });
      }
      const restaurant = await storage.getRestaurant(order.restaurantId);
      if (!restaurant) {
        return res.status(404).json({ error: "Restaurant not found" });
      }
      res.json(restaurant);
    } catch (error) {
      console.error("Error fetching restaurant for order:", error);
      res.status(500).json({ error: "Failed to fetch restaurant" });
    }
  });
  app2.get("/api/rewards", async (_req, res) => {
    try {
      const rewards2 = await storage.getActiveRewards();
      res.json(rewards2);
    } catch (error) {
      console.error("Error fetching rewards:", error);
      res.status(500).json({ error: "Failed to fetch rewards" });
    }
  });
  app2.post("/api/rewards/:id/redeem", isAuthenticated, async (req, res) => {
    try {
      const userId = req.user.claims ? req.user.claims.sub : req.user.id;
      const rewardId = req.params.id;
      const reward = await storage.getReward(rewardId);
      if (!reward) {
        return res.status(404).json({ error: "Reward not found" });
      }
      const user = await storage.getUser(userId);
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }
      if (user.points < reward.pointsCost) {
        return res.status(400).json({ error: "Insufficient points" });
      }
      if (reward.stock !== -1 && reward.stock <= 0) {
        return res.status(400).json({ error: "Reward out of stock" });
      }
      const redemption = await storage.createRedemption({
        userId,
        rewardId,
        rewardName: reward.name,
        pointsSpent: reward.pointsCost,
        status: "pending",
        usedAt: null
      });
      await storage.subtractUserPoints(userId, reward.pointsCost);
      if (reward.stock !== -1) {
        await storage.updateReward(rewardId, { stock: reward.stock - 1 });
      }
      res.status(201).json(redemption);
    } catch (error) {
      console.error("Error redeeming reward:", error);
      res.status(500).json({ error: "Failed to redeem reward" });
    }
  });
  app2.get("/api/rewards/redemptions", isAuthenticated, async (req, res) => {
    try {
      const userId = req.user.claims ? req.user.claims.sub : req.user.id;
      const redemptions = await storage.getUserRedemptions(userId);
      res.json(redemptions);
    } catch (error) {
      console.error("Error fetching redemptions:", error);
      res.status(500).json({ error: "Failed to fetch redemptions" });
    }
  });
  app2.get("/api/admin/products", isAdmin, async (_req, res) => {
    try {
      const restaurants2 = await storage.getAllRestaurants();
      if (restaurants2.length === 0) {
        return res.json([]);
      }
      const products2 = await storage.getProductsByRestaurant(restaurants2[0].id);
      res.json(products2);
    } catch (error) {
      console.error("Error fetching products:", error);
      res.status(500).json({ error: "Failed to fetch products" });
    }
  });
  app2.get("/api/admin/orders", isAdmin, async (_req, res) => {
    try {
      const orders2 = await storage.getAllOrders();
      res.json(orders2);
    } catch (error) {
      console.error("Error fetching all orders:", error);
      res.status(500).json({ error: "Failed to fetch orders" });
    }
  });
  app2.patch("/api/admin/products/:id", isAdmin, async (req, res) => {
    try {
      const { name, description, price, category, image } = req.body;
      const updates = {};
      if (name) updates.name = name;
      if (description) updates.description = description;
      if (price !== void 0) updates.price = price;
      if (category) updates.category = category;
      if (image) updates.image = image;
      const product = await storage.updateProduct(req.params.id, updates);
      if (!product) {
        return res.status(404).json({ error: "Product not found" });
      }
      res.json(product);
    } catch (error) {
      console.error("Error updating product:", error);
      res.status(500).json({ error: "Failed to update product" });
    }
  });
  app2.post("/api/admin/products", isAdmin, async (req, res) => {
    try {
      const { restaurantId, name, description, price, category, image } = req.body;
      const product = await storage.createProduct({
        restaurantId,
        name,
        description,
        price,
        category,
        image
      });
      res.status(201).json(product);
    } catch (error) {
      console.error("Error creating product:", error);
      res.status(500).json({ error: "Failed to create product" });
    }
  });
  app2.delete("/api/admin/products/:id", isAdmin, async (req, res) => {
    try {
      await storage.deleteProduct(req.params.id);
      res.status(204).send();
    } catch (error) {
      console.error("Error deleting product:", error);
      res.status(500).json({ error: "Failed to delete product" });
    }
  });
  const httpServer = createServer(app2);
  return httpServer;
}

// server/vite.ts
import express from "express";
import fs from "fs";
import path2 from "path";
import { createServer as createViteServer, createLogger } from "vite";

// vite.config.ts
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";
import runtimeErrorOverlay from "@replit/vite-plugin-runtime-error-modal";
var vite_config_default = defineConfig({
  plugins: [
    react(),
    runtimeErrorOverlay(),
    ...process.env.NODE_ENV !== "production" && process.env.REPL_ID !== void 0 ? [
      await import("@replit/vite-plugin-cartographer").then(
        (m) => m.cartographer()
      ),
      await import("@replit/vite-plugin-dev-banner").then(
        (m) => m.devBanner()
      )
    ] : []
  ],
  resolve: {
    alias: {
      "@": path.resolve(import.meta.dirname, "client", "src"),
      "@shared": path.resolve(import.meta.dirname, "shared"),
      "@assets": path.resolve(import.meta.dirname, "attached_assets")
    }
  },
  root: path.resolve(import.meta.dirname, "client"),
  build: {
    outDir: path.resolve(import.meta.dirname, "dist/public"),
    emptyOutDir: true
  },
  server: {
    fs: {
      strict: true,
      deny: ["**/.*"]
    }
  }
});

// server/vite.ts
import { nanoid } from "nanoid";
var viteLogger = createLogger();
function log(message, source = "express") {
  const formattedTime = (/* @__PURE__ */ new Date()).toLocaleTimeString("en-US", {
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit",
    hour12: true
  });
  console.log(`${formattedTime} [${source}] ${message}`);
}
async function setupVite(app2, server) {
  const serverOptions = {
    middlewareMode: true,
    hmr: { server },
    allowedHosts: true
  };
  const vite = await createViteServer({
    ...vite_config_default,
    configFile: false,
    customLogger: {
      ...viteLogger,
      error: (msg, options) => {
        viteLogger.error(msg, options);
        process.exit(1);
      }
    },
    server: serverOptions,
    appType: "custom"
  });
  app2.use(vite.middlewares);
  app2.use("*", async (req, res, next) => {
    const url = req.originalUrl;
    try {
      const clientTemplate = path2.resolve(
        import.meta.dirname,
        "..",
        "client",
        "index.html"
      );
      let template = await fs.promises.readFile(clientTemplate, "utf-8");
      template = template.replace(
        `src="/src/main.tsx"`,
        `src="/src/main.tsx?v=${nanoid()}"`
      );
      const page = await vite.transformIndexHtml(url, template);
      res.status(200).set({ "Content-Type": "text/html" }).end(page);
    } catch (e) {
      vite.ssrFixStacktrace(e);
      next(e);
    }
  });
}
function serveStatic(app2) {
  const distPath = path2.resolve(import.meta.dirname, "public");
  if (!fs.existsSync(distPath)) {
    throw new Error(
      `Could not find the build directory: ${distPath}, make sure to build the client first`
    );
  }
  app2.use(express.static(distPath));
  app2.use("*", (_req, res) => {
    res.sendFile(path2.resolve(distPath, "index.html"));
  });
}

// server/index.ts
var app = express2();
app.use(express2.json({
  verify: (req, _res, buf) => {
    req.rawBody = buf;
  }
}));
app.use(express2.urlencoded({ extended: false }));
app.use((req, res, next) => {
  const start = Date.now();
  const path3 = req.path;
  let capturedJsonResponse = void 0;
  const originalResJson = res.json;
  res.json = function(bodyJson, ...args) {
    capturedJsonResponse = bodyJson;
    return originalResJson.apply(res, [bodyJson, ...args]);
  };
  res.on("finish", () => {
    const duration = Date.now() - start;
    if (path3.startsWith("/api")) {
      let logLine = `${req.method} ${path3} ${res.statusCode} in ${duration}ms`;
      if (capturedJsonResponse) {
        logLine += ` :: ${JSON.stringify(capturedJsonResponse)}`;
      }
      if (logLine.length > 80) {
        logLine = logLine.slice(0, 79) + "\u2026";
      }
      log(logLine);
    }
  });
  next();
});
(async () => {
  const { seedDatabase: seedDatabase2 } = await Promise.resolve().then(() => (init_seed(), seed_exports));
  await seedDatabase2();
  const server = await registerRoutes(app);
  const { setupWebSocket: setupWebSocket2 } = await Promise.resolve().then(() => (init_websocket(), websocket_exports));
  setupWebSocket2(server);
  app.use((err, _req, res, _next) => {
    const status = err.status || err.statusCode || 500;
    const message = err.message || "Internal Server Error";
    res.status(status).json({ message });
    throw err;
  });
  if (app.get("env") === "development") {
    await setupVite(app, server);
  } else {
    serveStatic(app);
  }
  const port = parseInt(process.env.PORT || "5000", 10);
  server.listen({
    port,
    host: "0.0.0.0",
    reusePort: true
  }, () => {
    log(`serving on port ${port}`);
  });
})();
