import express from "express";
import crypto from "crypto";

const app = express();
app.use(express.raw({ type: "application/json" }));

function verifyShopifyHmac(req) {
  const hmacHeader = req.get("X-Shopify-Hmac-Sha256");
  if (!hmacHeader) return false;

  const digest = crypto
    .createHmac("sha256", process.env.SHOPIFY_WEBHOOK_SECRET)
    .update(req.body)
    .digest("base64");

  return crypto.timingSafeEqual(
    Buffer.from(digest, "utf8"),
    Buffer.from(hmacHeader, "utf8")
  );
}

app.post("/webhooks/shopify/orders", async (req, res) => {
  if (!verifyShopifyHmac(req)) {
    return res.status(401).send("Invalid HMAC");
  }

  console.log("Webhook received!");

  return res.status(200).send("OK");
});

app.get("/", (req, res) => {
  res.send("Webhook server is running");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
