const { newEnforcer } = require("casbin");
const path = require("path");

async function setupCasbin() {
    const enforcer = await newEnforcer(
        path.join(__dirname, "model.conf"),
        path.join(__dirname, "policy.csv")
    );

    return enforcer;
}

module.exports = setupCasbin;
