// Middleware to authorize routes based on user roles
module.exports = (allowedRoles = []) => {
    // Convert single string role to array
    if (typeof allowedRoles === "string") {
        allowedRoles = [allowedRoles];
    }

    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({
                message: "Access Denied: User is not authenticated."
            });
        }

        const userRole = req.user.role;

        // Check if user has permission
        if (allowedRoles.length > 0 && !allowedRoles.includes(userRole)) {
            return res.status(403).json({
                message: `Access Denied: Role '${userRole}' is not authorized to access this resource.`
            });
        }

        next();
    };
};
