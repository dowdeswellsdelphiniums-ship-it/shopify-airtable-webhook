
import express from "express";
import crypto from "crypto";

const app = express();
app.use(express.raw({ type: "application/json" }));

function verifyShopifyHmac(req) {
  try {
    const hmacHeader = req.get("X-Shopify-Hmac-Sha256");
    const secret = process.env.SHOPIFY_WEBHOOK_SECRET;

    if (!hmacHeader || !secret) return false;

    const digest = crypto
      .createHmac("sha256", secret)
      .update(req.body)
      .digest("base64");

    const a = Buffer.from(digest, "utf8");
    const b = Buffer.from(hmacHeader, "utf8");
    if (a.length !== b.length) return false;

    return crypto.timingSafeEqual(a, b);
  } catch (e) {
    console.error("HMAC verify error:", e);
    return false;
  }
}

app.post("/webhooks/shopify/orders", async (req, res) => {
  const ok = verifyShopifyHmac(req);

  if (!ok) {
    console.log("Webhook arrived but signature did NOT verify (no crash).");
    return res.status(401).send("Invalid HMAC");
  }

  console.log("Webhook verified OK!");
  return res.status(200).send("OK");
});

app.get("/", (req, res) => {
  res.send("Webhook server is running");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
