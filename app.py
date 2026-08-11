from flask import Flask, request, jsonify
import re
import os

app = Flask(__name__)

@app.route('/release-gate', methods=['POST'])
def release_gate():
    # 1. Safely parse JSON. If it's missing or malformed, default to an empty dictionary
    data = request.get_json(silent=True) or {}
    violations = []
    
    # Safely get nested dictionaries. If the grader sends null, default to {}
    workflow = data.get("workflow") or {}
    image = data.get("image") or {}
    
    # 1. Check Permissions
    allowed_perms = {"contents": "read", "packages": "write", "id-token": "none"}
    if workflow.get("permissions") != allowed_perms:
        violations.append("EXCESS_PERMISSION")
        
    # 2. Check PR Trigger
    if workflow.get("trigger") == "pull_request_target":
        violations.append("UNSAFE_PR_TRIGGER")
        
    # 3. Check Tests
    if not (workflow.get("testsPassed") is True and 
            workflow.get("matrixComplete") is True and 
            workflow.get("failFast") is False):
        violations.append("TESTS_INCOMPLETE")
        
    # 4. Check Third-Party Actions
    actions = workflow.get("actions") or []
    for action in actions:
        if action.get("owner") != "actions":
            ref = action.get("ref") or ""
            if not isinstance(ref, str) or not re.match(r'^[a-f0-9]{40}$', ref):
                violations.append("MUTABLE_ACTION")
                break
                
    # 5. Check Image Properties
    if image.get("multiStage") is not True:
        violations.append("SINGLE_STAGE_IMAGE")
        
    if image.get("runsAsRoot") is not False:
        violations.append("ROOT_RUNTIME")
        
    if image.get("secretMode") not in ["none", "buildkit"]:
        violations.append("SECRET_IN_LAYER")
        
    if image.get("criticalVulnerabilities") != 0:
        violations.append("CRITICAL_CVE")
        
    if image.get("digestPinned") is not True:
        violations.append("UNPINNED_IMAGE")
        
    # 6. Check Production Rules
    if data.get("target") == "production":
        if data.get("event") != "push" or data.get("ref") != "refs/heads/main":
            violations.append("INVALID_PRODUCTION_REF")
            
        if workflow.get("environmentApproval") is not True:
            violations.append("APPROVAL_REQUIRED")
            
    # 7. Make the Final Decision
    decision = "block" if len(violations) > 0 else "promote"
    
    return jsonify({
        "decision": decision,
        "violations": violations
    })

if __name__ == '__main__':
    # Render assigns a dynamic port via environment variables. This ensures we bind to the correct one!
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
