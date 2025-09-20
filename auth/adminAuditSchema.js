var mongoose = require ('mongoose');

var AdminAuditSchema = new mongoose.Schema({
  actor_id: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  action: { 
    type: String, 
    enum: ["approve_listing", "reject_listing", "block_user", "deactivate_listing"], 
    required: true 
  },
  target_type: { type: String, enum: ["listing", "user", "eoi"], required: true },
  target_id: { type: mongoose.Schema.Types.ObjectId, required: true },
  reason: { type: String },
  from_status: { type: String },
  to_status: { type: String },
  status: { type: String },

  created_at: { type: Date, default: Date.now }
});

mongoose.model('AdminAudit',AdminAuditSchema);

module.exports = mongoose.model('AdminAudit')