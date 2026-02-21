
import express from "express";
import crypto from "crypto";

const app = express();
app.use(express.raw({ type: "application/json" }));

app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} ${req.method} ${req.originalUrl}`);
  next();
});

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
    console.error("received (unverified)", e);
    return false;
  }
}

app.post("/webhooks/shopify/orders", async (req, res) => {
  console.log(`${new Date().toISOString()} POST /webhooks/shopify/orders`);

  let order;
  try {
    order = JSON.parse(req.body.toString("utf8"));
  } catch (e) {
    console.error("Could not parse JSON:", e);
    return res.status(400).send("bad json");
  }

  const rawJson = JSON.stringify(order);

  const fields = {
    "Shopify Order ID": String(order.id ?? ""),
    "Order Name": order.name ?? "",
    "Created At": order.created_at ? new Date(order.created_at).toISOString() : "",
    "Financial Status": order.financial_status ?? "",
    "Fulfillment Status": order.fulfillment_status ?? "",
    "Customer Email": order.email ?? order?.customer?.email ?? "",
    "Shipping Country": order?.shipping_address?.country ?? "",
    "Tags": order.tags ?? "",
    "Total Price": order.total_price ? Number(order.total_price) : null,
    "Raw JSON": rawJson,
  };

  if (!fields["Shopify Order ID"]) {
    console.error("Missing order.id in payload");
    return res.status(200).send("missing id (ignored)");
  }

  try {
    const url = `https://api.airtable.com/v0/${process.env.AIRTABLE_BASE_ID}/${encodeURIComponent(
      process.env.AIRTABLE_ORDERS_TABLE
    )}`;

    const resp = await fetch(url, {
      method: "PATCH",
      headers: {
        Authorization: `Bearer ${process.env.AIRTABLE_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        performUpsert: { fieldsToMergeOn: ["Shopify Order ID"] },
        records: [{ fields }],
      }),
    });

    if (!resp.ok) {
      const txt = await resp.text();
      console.error("Airtable error:", txt);
      return res.status(200).send("airtable error logged");
    }

    console.log("✅ Upserted order to Airtable:", fields["Shopify Order ID"]);
    return res.status(200).send("ok");
  } catch (e) {
    console.error("Airtable request failed:", e);
    return res.status(200).send("airtable exception logged");
  }
});

app.get("/", (req, res) => {
  res.send("Webhook server is running");
});

app.get("/ping", (req, res) => {
  res.send("pong");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
