const mongoose = require("mongoose");

const TenantSchema = new mongoose.Schema({
    _id: String,  // Microsoft Tenant ID
    name: String,
    plan: String
});

module.exports = mongoose.model("Tenant", TenantSchema);
