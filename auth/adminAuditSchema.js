var mongoose = require ('mongoose');

var AdminAuditSchema = new mongoose.Schema({
  actor_id: mongoose.Types.ObjectId,
  action: String,                  
  target_type: String,
  created_at: String,
  target_id: mongoose.Types.ObjectId,
  reason: String,
  status: String,
  from_status: String,
  to_status: String,


})

mongoose.model('AdminAudit',AdminAuditSchema);

module.exports = mongoose.model('AdminAudit')