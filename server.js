// server.js
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const bodyParser = require('body-parser');

// Custom middleware to handle application/reports+json content type
// This MUST come BEFORE other middleware
app.use((req, res, next) => {
    const contentType = req.headers['content-type'] || '';

    if (contentType.includes('application/reports+json') ||
        contentType.includes('application/csp-report')) {

        // For these special content types, use raw body parser
        let data = '';

        req.on('data', chunk => {
            data += chunk;
        });

        req.on('end', () => {
            try {
                if (data && data.trim()) {
                    req.body = JSON.parse(data);
                } else {
                    // Handle empty body case
                    req.body = {};
                }
                next();
            } catch (e) {
                console.error('Error parsing reports+json body:', e);
                // Log the raw data for debugging
                console.log('Raw body content (first 1000 chars):', data.substring(0, 1000));
                // Still continue even if parsing fails
                req.body = { rawData: data.substring(0, 1000) + '...' };
                next();
            }
        });
    } else {
        // For other content types, proceed to next middleware
        next();
    }
});

// Standard middleware - AFTER the custom middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI)
    .then(() => console.log('Connected to MongoDB'))
    .catch(err => console.error('MongoDB connection error:', err));

// Define schema for customers
const customerSchema = new mongoose.Schema({
    name: { type: String, required: true },
    uniqueId: { type: String, required: true, unique: true },
    createdAt: { type: Date, default: Date.now }
});

// Define schema for CSP violations
const violationSchema = new mongoose.Schema({
    customerId: { type: String, required: true, index: true },
    reportData: {
        'document-uri': String,
        'violated-directive': String,
        // Other possible fields from Magento
        'blocked-uri': String,
        'source-file': String,
        'line-number': Number,
        'column-number': Number,
        'effective-directive': String
    },
    userAgent: String,
    ipAddress: String,
    timestamp: { type: Date, default: Date.now }
});

// Create models
const Customer = mongoose.model('Customer', customerSchema);
const Violation = mongoose.model('Violation', violationSchema);

// Update your CSP report endpoint to handle the Reports API format
app.post('/csp-report/:uniqueId', async (req, res) => {
    try {
        const { uniqueId } = req.params;

        // Verify the uniqueId exists
        const customer = await Customer.findOne({ uniqueId });
        if (!customer) {
            return res.status(404).json({ error: 'Invalid reporting endpoint' });
        }

        // Handle different report formats
        let reportData;

        // Check if this is Reports API format (array of reports)
        if (Array.isArray(req.body)) {
            // Reports API format - extract the first CSP report
            const cspReports = req.body.filter(report =>
                report.type === 'csp-violation' ||
                report.body?.['csp-report']
            );

            if (cspReports.length > 0) {
                // Use the first CSP report
                const firstReport = cspReports[0];
                reportData = firstReport.body?.['csp-report'] || firstReport.body || firstReport;
            } else {
                // No CSP reports found in the array
                reportData = {
                    'document-uri': 'Unknown (No CSP reports in array)',
                    'violated-directive': 'Unknown',
                    'blocked-uri': 'Unknown'
                };
            }
        }
        // Standard browser format with csp-report
        else if (req.body['csp-report']) {
            reportData = req.body['csp-report'];
        }
        // Other possible formats
        else if (req.body.report) {
            reportData = req.body.report;
        } else if (req.body['content-security-policy-report']) {
            reportData = req.body['content-security-policy-report'];
        }
        // Handle the case where body is empty or doesn't match expected format
        else if (Object.keys(req.body).length === 0 ||
            (!req.body['document-uri'] && !req.body['violated-directive'])) {

            reportData = {
                'document-uri': 'Unknown (Empty or Invalid Format)',
                'violated-directive': 'Unknown',
                'blocked-uri': 'Unknown',
                'original-report': JSON.stringify(req.body)
            };
        }
        // Check for rawData from failed parsing
        else if (req.body.rawData) {
            reportData = {
                'document-uri': 'Unknown (Parsing Error)',
                'violated-directive': 'Unknown',
                'blocked-uri': 'Unknown',
                'original-report': req.body.rawData
            };
        }
        // Assume the body itself contains the report
        else {
            reportData = req.body;
        }


        // Create new violation record
        const violation = new Violation({
            customerId: customer.uniqueId,
            reportData: reportData,
            userAgent: req.headers['user-agent'],
            ipAddress: req.headers['cf-connecting-ip'] || req.headers['x-forwarded-for'] || req.ip
        });

        await violation.save();

        // CSP spec recommends returning 204 No Content
        return res.status(204).end();
    } catch (error) {
        console.error('Error processing CSP report:', error);
        return res.status(500).json({ error: 'Internal server error' });
    }
});

// 2. Customer management - create new customer
app.post('/api/customers', async (req, res) => {
    try {
        const { name } = req.body;

        if (!name) {
            return res.status(400).json({ error: 'Name is required' });
        }

        // Generate unique ID for the customer
        const uniqueId = uuidv4();

        const customer = new Customer({
            name,
            uniqueId
        });

        await customer.save();

        // Return the customer data with reporting URL
        return res.status(201).json({
            id: customer._id,
            name: customer.name,
            uniqueId: customer.uniqueId,
            reportingUrl: `${process.env.API_BASE_URL}/csp-report/${customer.uniqueId}`
        });
    } catch (error) {
        console.error('Error creating customer:', error);
        return res.status(500).json({ error: 'Internal server error' });
    }
});

// 3. Get customer by uniqueId (for dashboard auth)
app.get('/api/customers/:uniqueId', async (req, res) => {
    try {
        const { uniqueId } = req.params;

        const customer = await Customer.findOne({ uniqueId });
        if (!customer) {
            return res.status(404).json({ error: 'Customer not found' });
        }

        return res.json({
            id: customer._id,
            name: customer.name,
            uniqueId: customer.uniqueId,
            createdAt: customer.createdAt
        });
    } catch (error) {
        console.error('Error fetching customer:', error);
        return res.status(500).json({ error: 'Internal server error' });
    }
});

// 4. Get violations for a customer
app.get('/api/violations/:uniqueId', async (req, res) => {
    try {
        const { uniqueId } = req.params;
        const { limit = 100, skip = 0 } = req.query;

        // Verify the uniqueId exists
        const customer = await Customer.findOne({ uniqueId });
        if (!customer) {
            return res.status(404).json({ error: 'Customer not found' });
        }

        // Get violations with pagination
        const violations = await Violation.find({ customerId: uniqueId })
            .sort({ timestamp: -1 })
            .skip(Number(skip))
            .limit(Number(limit));

        // Get total count
        const total = await Violation.countDocuments({ customerId: uniqueId });

        return res.json({
            violations,
            pagination: {
                total,
                limit: Number(limit),
                skip: Number(skip)
            }
        });
    } catch (error) {
        console.error('Error fetching violations:', error);
        return res.status(500).json({ error: 'Internal server error' });
    }
});

// 5. Get violation statistics for a customer
app.get('/api/stats/:uniqueId', async (req, res) => {
    try {
        const { uniqueId } = req.params;
        const { days = 7 } = req.query;

        // Verify the uniqueId exists
        const customer = await Customer.findOne({ uniqueId });
        if (!customer) {
            return res.status(404).json({ error: 'Customer not found' });
        }

        // Calculate date range
        const endDate = new Date();
        const startDate = new Date();
        startDate.setDate(startDate.getDate() - Number(days));

        // Get count by directive
        const directiveCounts = await Violation.aggregate([
            {
                $match: {
                    customerId: uniqueId,
                    timestamp: { $gte: startDate, $lte: endDate }
                }
            },
            {
                $group: {
                    _id: "$reportData.violated-directive",
                    count: { $sum: 1 }
                }
            },
            { $sort: { count: -1 } }
        ]);

        // Get count by blocked URI
        const uriCounts = await Violation.aggregate([
            {
                $match: {
                    customerId: uniqueId,
                    timestamp: { $gte: startDate, $lte: endDate }
                }
            },
            {
                $group: {
                    _id: "$reportData.blocked-uri",
                    count: { $sum: 1 }
                }
            },
            { $sort: { count: -1 } },
            { $limit: 10 }
        ]);

        // Get daily counts
        const dailyCounts = await Violation.aggregate([
            {
                $match: {
                    customerId: uniqueId,
                    timestamp: { $gte: startDate, $lte: endDate }
                }
            },
            {
                $group: {
                    _id: {
                        $dateToString: { format: "%Y-%m-%d", date: "$timestamp" }
                    },
                    count: { $sum: 1 }
                }
            },
            { $sort: { "_id": 1 } }
        ]);

        return res.json({
            totalViolations: await Violation.countDocuments({
                customerId: uniqueId,
                timestamp: { $gte: startDate, $lte: endDate }
            }),
            byDirective: directiveCounts,
            byUri: uriCounts,
            byDay: dailyCounts
        });
    } catch (error) {
        console.error('Error fetching statistics:', error);
        return res.status(500).json({ error: 'Internal server error' });
    }
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});