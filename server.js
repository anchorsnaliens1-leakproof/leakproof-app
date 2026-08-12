const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const { v4: uuid } = require("uuid");
const low = require("lowdb");
const FileSync = require("lowdb/adapters/FileSync");
const path = require("path");
const vendors = require("./vendors");

// ---- Stripe (optional — app works fine without keys set, "Upgrade" just won't charge) ----
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || "";
const STRIPE_PRICE_ID = process.env.STRIPE_PRICE_ID || "";
const stripe = STRIPE_SECRET_KEY ? require("stripe")(STRIPE_SECRET_KEY) : null;

// ---- DB setup ----
const adapter = new FileSync(path.join(__dirname, "db.json"));
const db = low(adapter);
db.defaults({ users: [], subscriptions: [] }).write();

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));
app.use(
  session({
    secret: process.env.SESSION_SECRET || "change-this-secret-in-production",
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 1000 * 60 * 60 * 24 * 30 } // 30 days
  })
);

function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: "Not logged in" });
  next();
}

function getUser(req) {
  return db.get("users").find({ id: req.session.userId }).value();
}

// ---------------- AUTH ----------------

app.post("/api/signup", (req, res) => {
  const { email, password } = req.body;
  if (!email || !password || password.length < 6) {
    return res.status(400).json({ error: "Email and a password of 6+ characters are required." });
  }
  const existing = db.get("users").find({ email: email.toLowerCase() }).value();
  if (existing) return res.status(400).json({ error: "An account with that email already exists." });

  const user = {
    id: uuid(),
    email: email.toLowerCase(),
    passwordHash: bcrypt.hashSync(password, 10),
    premium: false,
    createdAt: new Date().toISOString()
  };
  db.get("users").push(user).write();
  req.session.userId = user.id;
  res.json({ email: user.email, premium: user.premium });
});

app.post("/api/login", (req, res) => {
  const { email, password } = req.body;
  const user = db.get("users").find({ email: (email || "").toLowerCase() }).value();
  if (!user || !bcrypt.compareSync(password || "", user.passwordHash)) {
    return res.status(401).json({ error: "Invalid email or password." });
  }
  req.session.userId = user.id;
  res.json({ email: user.email, premium: user.premium });
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get("/api/me", (req, res) => {
  const user = getUser(req);
  if (!user) return res.status(401).json({ error: "Not logged in" });
  res.json({ email: user.email, premium: user.premium });
});

// ---------------- VENDORS ----------------

app.get("/api/vendors", (req, res) => res.json(vendors));

// ---------------- SUBSCRIPTIONS ----------------

app.get("/api/subscriptions", requireAuth, (req, res) => {
  const subs = db.get("subscriptions").filter({ userId: req.session.userId }).value();
  res.json(subs);
});

app.post("/api/subscriptions", requireAuth, (req, res) => {
  const { name, cost, billingCycle, renewalDate, lastUsed, cancelUrl } = req.body;
  if (!name || !cost) return res.status(400).json({ error: "Name and monthly cost are required." });

  const sub = {
    id: uuid(),
    userId: req.session.userId,
    name,
    cost: Number(cost),
    billingCycle: billingCycle || "monthly",
    renewalDate: renewalDate || null,
    lastUsed: lastUsed || null,
    cancelUrl: cancelUrl || "",
    createdAt: new Date().toISOString()
  };
  db.get("subscriptions").push(sub).write();
  res.json(sub);
});

app.put("/api/subscriptions/:id", requireAuth, (req, res) => {
  const sub = db.get("subscriptions").find({ id: req.params.id, userId: req.session.userId }).value();
  if (!sub) return res.status(404).json({ error: "Not found" });
  const updates = (({ name, cost, billingCycle, renewalDate, lastUsed, cancelUrl }) => ({
    name, cost, billingCycle, renewalDate, lastUsed, cancelUrl
  }))(req.body);
  Object.keys(updates).forEach((k) => updates[k] === undefined && delete updates[k]);
  if (updates.cost !== undefined) updates.cost = Number(updates.cost);

  db.get("subscriptions").find({ id: req.params.id }).assign(updates).write();
  res.json(db.get("subscriptions").find({ id: req.params.id }).value());
});

app.delete("/api/subscriptions/:id", requireAuth, (req, res) => {
  db.get("subscriptions").remove({ id: req.params.id, userId: req.session.userId }).write();
  res.json({ ok: true });
});

// ---------------- STATS / WASTE DETECTION ----------------

app.get("/api/stats", requireAuth, (req, res) => {
  const user = getUser(req);
  const subs = db.get("subscriptions").filter({ userId: req.session.userId }).value();

  const monthlyTotal = subs.reduce((sum, s) => {
    const monthlyCost = s.billingCycle === "yearly" ? s.cost / 12 : s.cost;
    return sum + monthlyCost;
  }, 0);

  const now = new Date();
  const wasteThresholdDays = 30;

  const flagged = subs.filter((s) => {
    if (!s.lastUsed) return true; // never marked as used = flag it
    const daysSince = (now - new Date(s.lastUsed)) / (1000 * 60 * 60 * 24);
    return daysSince > wasteThresholdDays;
  });

  const wastedMonthly = flagged.reduce((sum, s) => {
    const monthlyCost = s.billingCycle === "yearly" ? s.cost / 12 : s.cost;
    return sum + monthlyCost;
  }, 0);

  res.json({
    monthlyTotal: Math.round(monthlyTotal * 100) / 100,
    annualTotal: Math.round(monthlyTotal * 12 * 100) / 100,
    toolCount: subs.length,
    premium: user.premium,
    // waste details are only meaningful to the user on the premium tier
    flaggedCount: user.premium ? flagged.length : null,
    wastedMonthly: user.premium ? Math.round(wastedMonthly * 100) / 100 : null,
    flaggedTools: user.premium ? flagged.map((s) => ({ id: s.id, name: s.name, cost: s.cost })) : null
  });
});

// ---------------- STRIPE CHECKOUT (premium upgrade) ----------------

app.post("/api/create-checkout-session", requireAuth, async (req, res) => {
  if (!stripe || !STRIPE_PRICE_ID) {
    // Demo mode: no Stripe keys configured yet — just flip the flag so you can test the flow.
    db.get("users").find({ id: req.session.userId }).assign({ premium: true }).write();
    return res.json({ demoMode: true, upgraded: true });
  }
  try {
    const session = await stripe.checkout.sessions.create({
      mode: "subscription",
      line_items: [{ price: STRIPE_PRICE_ID, quantity: 1 }],
      success_url: `${req.protocol}://${req.get("host")}/?upgraded=1`,
      cancel_url: `${req.protocol}://${req.get("host")}/`,
      client_reference_id: req.session.userId
    });
    res.json({ url: session.url });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not start checkout." });
  }
});

// Stripe webhook to confirm payment and flip the premium flag for real.
// Set STRIPE_WEBHOOK_SECRET and point your Stripe webhook at /api/stripe-webhook.
app.post("/api/stripe-webhook", express.raw({ type: "application/json" }), (req, res) => {
  if (!stripe) return res.status(400).send("Stripe not configured");
  const sig = req.headers["stripe-signature"];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }
  if (event.type === "checkout.session.completed") {
    const session = event.data.object;
    const userId = session.client_reference_id;
    if (userId) db.get("users").find({ id: userId }).assign({ premium: true }).write();
  }
  res.json({ received: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`AI Tool Tracker running on port ${PORT}`));
