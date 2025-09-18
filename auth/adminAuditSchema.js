var mongoose = require ('mongoose');

var AdminAuditSchema = new mongoose.Schema({


})

mongoose.model('AdminAudit',AdminAuditSchema);

module.exports = mongoose.model('AdminAudit')