// server.js
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
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

// Routes
// 1. CSP Report endpoint
app.post('/csp-report/:uniqueId', async (req, res) => {
    try {
        const { uniqueId } = req.params;

        // Verify the uniqueId exists
        const customer = await Customer.findOne({ uniqueId });
        if (!customer) {
            return res.status(404).json({ error: 'Invalid reporting endpoint' });
        }

        // Extract CSP report data
        // Check if the data is wrapped in a 'csp-report' object (standard browser format)
        const reportData = req.body['csp-report'] || req.body;

        // Create new violation record
        const violation = new Violation({
            customerId: customer.uniqueId,
            reportData: reportData,  // Store the report data in the correct field
            userAgent: req.headers['user-agent'],
            ipAddress: req.ip
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