var mongoose = require ('mongoose');

var AdminAuditSchema = new mongoose.Schema({
actor_id:Number,
action:String,
target_type:String,
target_id:Number,
meta:String,
created_at:String

})

mongoose.model('AdminAudit',AdminAuditSchema);

module.exports = mongoose.model('AdminAudit')