const express = require("express");
const mysql = require("mysql2");
const app = express();
const PORT = 3000;
const bcrypt = require("bcryptjs");
const bodyParser = require("body-parser");
const cors = require("cors");
require("dotenv").config(); // Load environment variables from .env file

app.use(express.json()); // Add this to parse JSON
app.use(cors());
app.use(bodyParser.json());

// Create the MySQL connection pool
const pool = mysql.createPool({
	host: process.env.DB_HOST,
	user: process.env.DB_USER,
	password: process.env.DB_PASSWORD,
	database: process.env.DB_NAME,
	waitForConnections: true,
	connectionLimit: 10,
	queueLimit: 0,
});

// Function to get a connection from the pool
function getConnectionWithRetry() {
	return new Promise((resolve, reject) => {
		pool.getConnection((err, connection) => {
			if (err) {
				console.error("Error getting connection from pool:", err);
				setTimeout(() => {
					getConnectionWithRetry().then(resolve).catch(reject); // Retry after 5 seconds
				}, 5000);
			} else {
				resolve(connection); // Return the connection to be used
			}
		});
	});
}

// User Signup API Endpoint
app.post("/api/signup", async (req, res) => {
	const { first_name, last_name, email, password, confirm_password } = req.body;

	// Basic validation
	if (!first_name || !last_name || !email || !password || !confirm_password) {
		return res.status(400).json({ error: "All fields are required" });
	}

	// Check if passwords match
	if (password !== confirm_password) {
		return res.status(400).json({ error: "Passwords do not match" });
	}

	const connection = await getConnectionWithRetry();
	try {
		// Check if email already exists
		const checkEmailQuery = "SELECT * FROM users WHERE email = ?";
		const [results] = await connection.query(checkEmailQuery, [email]);

		if (results.length > 0) {
			return res.status(400).json({ error: "Email already in use" });
		}

		// Hash the password before saving
		const hashedPassword = await bcrypt.hash(password, 10);

		// Insert new user into the database
		const insertQuery =
			"INSERT INTO users (first_name, last_name, email, password_hash) VALUES (?, ?, ?, ?)";
		const [insertResult] = await connection.query(insertQuery, [
			first_name,
			last_name,
			email,
			hashedPassword,
		]);

		res.status(201).json({
			message: "User  successfully created",
			userId: insertResult.insertId,
		});
	} catch (err) {
		console.error("Database error:", err);
		res.status(500).json({ error: "Database error", details: err.message });
	} finally {
		connection.release(); // Release connection back to the pool
	}
});

// User Sign-In API Endpoint
app.post("/api/signin", async (req, res) => {
	const { email, password } = req.body;

	// Basic validation
	if (!email || !password) {
		return res.status(400).json({ error: "Email and password are required" });
	}

	const connection = await getConnectionWithRetry();
	try {
		// Query the database to check if the email exists
		const query = "SELECT * FROM users WHERE email = ?";
		const [results] = await connection.query(query, [email]);

		if (results.length === 0) {
			return res.status(400).json({ error: "Invalid email or password" });
		}

		const user = results[0];

		// Compare the entered password with the hashed password in the database
		const isMatch = await bcrypt.compare(password, user.password_hash);
		if (!isMatch) {
			return res.status(400).json({ error: "Invalid email or password" });
		}

		// If passwords match, return success response
		res.status(200).json({
			message: "Sign-in successful",
			userId: user.id,
			firstName: user.first_name,
			lastName: user.last_name,
			email: user.email,
		});
	} catch (err) {
		console.error("Database error:", err);
		res.status(500).json({ error: "Database error", details: err.message });
	} finally {
		connection.release(); // Release connection back to the pool
	}
});

// Get all products
app.get("/api/products", async (req, res) => {
	const connection = await getConnectionWithRetry();

	try {
		const query = "SELECT * FROM products";

		const [results] = await connection.query(query);

		console.log(`Retrieved ${results.length} products`);

		// Optional: Log the first product for debugging
		if (results.length > 0) {
			console.log("First Product:", results[0]);
		}

		// Optional: Process results if needed
		const processedProducts = results.map((product) => ({
			...product,
			// Example of additional processing
			specifications: product.specs ? JSON.parse(product.specs) : null,
			// Format price to ensure consistent decimal representation
			price: parseFloat(product.price).toFixed(2),
		}));

		res.json(processedProducts);
	} catch (err) {
		console.error("Error retrieving products:", err.stack);
		res.status(500).json({
			error: "Error retrieving products",
			details: err.message,
			stack: process.env.NODE_ENV === "development" ? err.stack : undefined,
		});
	} finally {
		// Always release the connection back to the pool
		connection.release();
	}
});
app.post("/api/cart", async (req, res) => {
	const { user_id, product_id, quantity } = req.body;

	// Basic validation
	if (!user_id || !product_id || !quantity) {
		return res.status(400).json({
			error: "User ID, Product ID, and Quantity are required",
		});
	}

	const connection = await getConnectionWithRetry();

	try {
		// Check if the product already exists in the cart for the given user
		const [existingCartItems] = await connection.query(
			"SELECT * FROM cart WHERE user_id = ? AND product_id = ?",
			[user_id, product_id]
		);

		if (existingCartItems.length > 0) {
			// If the product already exists in the cart, add the new quantity to the existing quantity
			const newQuantity = existingCartItems[0].quantity + quantity;

			// Update the quantity
			await connection.query(
				"UPDATE cart SET quantity = ? WHERE user_id = ? AND product_id = ?",
				[newQuantity, user_id, product_id]
			);

			res.status(200).json({
				message: "Cart updated successfully",
				cartItem: {
					user_id,
					product_id,
					quantity: newQuantity,
				},
			});
		} else {
			// If the product doesn't exist in the cart, add it with the specified quantity
			await connection.query(
				"INSERT INTO cart (user_id, product_id, quantity) VALUES (?, ?, ?)",
				[user_id, product_id, quantity]
			);

			res.status(200).json({
				message: "Product added to cart successfully",
				cartItem: {
					user_id,
					product_id,
					quantity,
				},
			});
		}
	} catch (err) {
		console.error("Cart Error:", err);
		res.status(500).json({
			error: "Failed to manage cart",
			details: err.message,
			stack: process.env.NODE_ENV === "development" ? err.stack : undefined,
		});
	} finally {
		// Always release the connection back to the pool
		connection.release();
	}
});

// Enhanced version with additional checks
app.post("/api/cart", async (req, res) => {
	const { user_id, product_id, quantity } = req.body;

	// Comprehensive validation
	if (!user_id || !product_id || !quantity) {
		return res.status(400).json({
			error: "User ID, Product ID, and Quantity are required",
		});
	}

	// Validate quantity
	const parsedQuantity = parseInt(quantity, 10);
	if (isNaN(parsedQuantity) || parsedQuantity <= 0) {
		return res.status(400).json({
			error: "Quantity must be a positive number",
		});
	}

	const connection = await getConnectionWithRetry();

	try {
		// Start a transaction
		await connection.beginTransaction();

		// Verify product exists
		const [productCheck] = await connection.query(
			"SELECT id FROM products WHERE id = ?",
			[product_id]
		);

		if (productCheck.length === 0) {
			await connection.rollback();
			return res.status(404).json({
				error: "Product not found",
			});
		}

		// Check if the product already exists in the cart
		const [existingCartItems] = await connection.query(
			"SELECT * FROM cart WHERE user_id = ? AND product_id = ?",
			[user_id, product_id]
		);

		let result;
		if (existingCartItems.length > 0) {
			// Calculate new quantity
			const newQuantity = existingCartItems[0].quantity + parsedQuantity;

			// Update existing cart item
			await connection.query(
				"UPDATE cart SET quantity = ? WHERE user_id = ? AND product_id = ?",
				[newQuantity, user_id, product_id]
			);

			result = {
				message: "Cart updated successfully",
				cartItem: {
					user_id,
					product_id,
					quantity: newQuantity,
				},
			};
		} else {
			// Insert new cart item
			await connection.query(
				"INSERT INTO cart (user_id, product_id, quantity) VALUES (?, ?, ?)",
				[user_id, product_id, parsedQuantity]
			);

			result = {
				message: "Product added to cart successfully",
				cartItem: {
					user_id,
					product_id,
					quantity: parsedQuantity,
				},
			};
		}

		// Commit the transaction
		await connection.commit();

		res.status(200).json(result);
	} catch (err) {
		// Rollback the transaction in case of error
		await connection.rollback();

		console.error("Cart Management Error:", err);
		res.status(500).json({
			error: "Failed to manage cart",
			details: err.message,
			stack: process.env.NODE_ENV === "development" ? err.stack : undefined,
		});
	} finally {
		// Always release the connection
		connection.release();
	}
});

app.get("/api/cart/:userId", async (req, res) => {
	const userId = req.params.userId;
	console.log("Fetching cart for user", userId);

	if (!userId) {
		return res.status(400).json({ error: "User ID is required" });
	}

	const connection = await getConnectionWithRetry();

	try {
		const query = `
            SELECT 
                c.product_id, 
                c.quantity, 
                p.name, 
                p.price, 
                p.image
            FROM 
                cart c
            JOIN 
                products p ON c.product_id = p.id
            WHERE 
                c.user_id = ?
        `;

		const [results] = await connection.query(query, [userId]);

		// If no items in cart
		if (results.length === 0) {
			return res.status(200).json({
				message: "Cart is empty",
				cartItems: [],
				totalItems: 0,
				totalValue: 0,
			});
		}

		// Calculate total cart value
		const totalValue = results.reduce((total, item) => {
			return total + item.price * item.quantity;
		}, 0);

		res.status(200).json({
			cartItems: results,
			totalItems: results.length,
			totalValue: totalValue.toFixed(2),
		});
	} catch (err) {
		console.error("Database error:", err);
		res.status(500).json({
			error: "Error fetching cart",
			details: err.message,
			stack: process.env.NODE_ENV === "development" ? err.stack : undefined,
		});
	} finally {
		// Always release the connection back to the pool
		connection.release();
	}
});
app.post("/api/cart/update", async (req, res) => {
	const { userId, productId, quantity } = req.body;

	if (!userId || !productId || quantity === undefined) {
		return res
			.status(400)
			.json({ error: "User ID, Product ID, and Quantity are required" });
	}

	const connection = await getConnectionWithRetry();

	try {
		// If quantity is 0 or less, remove the item from the cart
		if (quantity <= 0) {
			const [result] = await connection.query(
				"DELETE FROM cart WHERE user_id = ? AND product_id = ?",
				[userId, productId]
			);

			return res.status(200).json({
				message: "Item removed from cart successfully",
			});
		} else {
			// Update or insert the cart item
			const upsertQuery = `
                INSERT INTO cart (user_id, product_id, quantity) 
                VALUES (?, ?, ?) 
                ON DUPLICATE KEY UPDATE quantity = ?
            `;

			const [result] = await connection.query(upsertQuery, [
				userId,
				productId,
				quantity,
				quantity,
			]);

			res.status(200).json({
				message: "Cart updated successfully",
			});
		}
	} catch (err) {
		console.error("Database error:", err);
		res.status(500).json({
			error: "Database error",
			details: err.message,
		});
	} finally {
		// Always release the connection back to the pool
		connection.release();
	}
});
app.delete("/api/cart/remove", async (req, res) => {
	const { userId, productId } = req.body;
	console.log("Removing item from cart", userId, productId);

	if (!userId || !productId) {
		return res
			.status(400)
			.json({ error: "User ID and Product ID are required" });
	}

	const connection = await getConnectionWithRetry();

	try {
		const removeQuery = "DELETE FROM cart WHERE user_id = ? AND product_id = ?";
		const [result] = await connection.query(removeQuery, [userId, productId]);

		// Check if any rows were actually deleted
		if (result.affectedRows === 0) {
			return res.status(404).json({
				error: "Item not found in cart",
			});
		}

		res.status(200).json({
			message: "Item removed from cart successfully",
			deletedRows: result.affectedRows,
		});
	} catch (err) {
		console.error("Database error:", err);
		res.status(500).json({
			error: "Database error",
			details: err.message,
		});
	} finally {
		// Always release the connection back to the pool
		connection.release();
	}
});

app.post("/api/cart/details", async (req, res) => {
	const { userId, productIds } = req.body;

	if (!userId || !productIds || !Array.isArray(productIds)) {
		return res
			.status(400)
			.json({ error: "User ID and Product IDs are required" });
	}

	const connection = await getConnectionWithRetry();

	try {
		// Get cart items with product details
		const query = `
            SELECT 
                p.id, 
                p.name, 
                p.description, 
                p.price, 
                p.image, 
                c.quantity
            FROM cart c
            JOIN products p ON c.product_id = p.id
            WHERE c.user_id = ? AND p.id IN (?)
        `;

		const [results] = await connection.query(query, [userId, productIds]);

		res.status(200).json(results);
	} catch (err) {
		console.error("Database error:", err);
		res.status(500).json({
			error: "Database error",
			details: err.message,
		});
	} finally {
		// Always release the connection back to the pool
		connection.release();
	}
});
app.post("/api/orders/place", async (req, res) => {
	const { userId, items } = req.body;

	if (!userId || !items || items.length === 0) {
		return res.status(400).json({ error: "User ID and items are required" });
	}

	const connection = await getConnectionWithRetry();

	try {
		// Start a transaction
		await connection.beginTransaction();

		// Calculate total amount
		const totalAmount = items.reduce((total, item) => {
			return total + item.price * item.quantity;
		}, 0);

		// Insert order
		const [orderResult] = await connection.query(
			"INSERT INTO orders (user_id, order_date, total_amount) VALUES (?, NOW(), ?)",
			[userId, totalAmount]
		);

		const orderId = orderResult.insertId;

		// Prepare order items
		const orderItemsQuery =
			"INSERT INTO order_items (order_id, product_id, quantity, price) VALUES ?";
		const orderItemsValues = items.map((item) => [
			orderId,
			item.id,
			item.quantity,
			item.price,
		]);

		await connection.query(orderItemsQuery, [orderItemsValues]);

		// Remove items from cart
		await connection.query("DELETE FROM cart WHERE user_id = ?", [userId]);

		// Commit the transaction
		await connection.commit();

		res.status(200).json({
			message: "Order placed successfully",
			orderId: orderId,
		});
	} catch (err) {
		// Rollback the transaction in case of any error
		await connection.rollback();

		console.error("Order placement error:", err);
		res.status(500).json({
			error: "Failed to place order",
			details: err.message,
		});
	} finally {
		// Always release the connection back to the pool
		connection.release();
	}
});
app.get("/api/orders", async (req, res) => {
	const { userId } = req.query;

	if (!userId) {
		return res.status(400).json({ error: "User ID is required" });
	}

	const connection = await getConnectionWithRetry();

	try {
		// First, get the orders
		const [orderResults] = await connection.query(
			`
            SELECT 
                o.id AS order_id, 
                o.order_date, 
                o.total_amount
            FROM orders o
            WHERE o.user_id = ?
            ORDER BY o.order_date DESC
        `,
			[userId]
		);

		// If no orders found, return empty array
		if (orderResults.length === 0) {
			return res.status(200).json([]);
		}

		// Prepare to fetch items for each order
		const orderIds = orderResults.map((order) => order.order_id);

		// Get order items for all orders in one query
		const [itemResults] = await connection.query(
			`
            SELECT 
                oi.order_id,
                oi.product_id,
                p.name,
                oi.price,
                oi.quantity,
                p.image
            FROM order_items oi
            JOIN products p ON oi.product_id = p.id
            WHERE oi.order_id IN (?)
        `,
			[orderIds]
		);

		// Group items by order
		const orderItemsMap = itemResults.reduce((acc, item) => {
			if (!acc[item.order_id]) {
				acc[item.order_id] = [];
			}
			acc[item.order_id].push({
				product_id: item.product_id,
				name: item.name,
				price: parseFloat(item.price),
				quantity: item.quantity,
				image: item.image,
			});
			return acc;
		}, {});

		// Combine orders with their items
		const processedOrders = orderResults.map((order) => ({
			id: `ORD-${order.order_id}`,
			date: new Date(order.order_date).toISOString().split("T")[0],
			total: parseFloat(order.total_amount),
			items: orderItemsMap[order.order_id] || [],
		}));

		res.status(200).json(processedOrders);
	} catch (err) {
		console.error("Orders Query Error:", err);
		res.status(500).json({
			error: "Failed to retrieve orders",
			details: err.message,
		});
	} finally {
		// Always release the connection back to the pool
		connection.release();
	}
});
app.get("/api/orders/:orderId", async (req, res) => {
	const { orderId } = req.params;
	const { userId } = req.query;

	if (!userId || !orderId) {
		return res.status(400).json({ error: "User ID and Order ID are required" });
	}

	// Extract numeric ID from formatted order ID
	const numericOrderId = orderId.replace("ORD-", "");

	const connection = await getConnectionWithRetry();

	try {
		// First, get the order details
		const [orderResults] = await connection.query(
			`
            SELECT 
                o.id AS order_id, 
                o.order_date, 
                o.total_amount
            FROM orders o
            WHERE o.id = ? AND o.user_id = ?
        `,
			[numericOrderId, userId]
		);

		if (orderResults.length === 0) {
			return res.status(404).json({ error: "Order not found" });
		}

		// Get order items
		const [itemResults] = await connection.query(
			`
            SELECT 
                oi.product_id,
                p.name,
                oi.price,
                oi.quantity,
                p.image
            FROM order_items oi
            JOIN products p ON oi.product_id = p.id
            WHERE oi.order_id = ?
        `,
			[numericOrderId]
		);

		const order = orderResults[0];
		const processedOrder = {
			id: `ORD-${order.order_id}`,
			date: new Date(order.order_date).toISOString().split("T")[0],
			total: parseFloat(order.total_amount),
			items: itemResults.map((item) => ({
				product_id: item.product_id,
				name: item.name,
				price: parseFloat(item.price),
				quantity: item.quantity,
				image: item.image,
			})),
		};

		res.status(200).json(processedOrder);
	} catch (err) {
		console.error("Order Details Query Error:", err);
		res.status(500).json({
			error: "Failed to retrieve order details",
			details: err.message,
		});
	} finally {
		// Always release the connection back to the pool
		connection.release();
	}
});
app.put("/api/cart/update-quantity", async (req, res) => {
	const { userId, productId, quantity } = req.body;

	if (!userId || !productId || quantity === undefined) {
		return res.status(400).json({
			error: "User ID, Product ID, and Quantity are required",
		});
	}

	// Validate quantity
	const parsedQuantity = parseInt(quantity, 10);
	if (isNaN(parsedQuantity) || parsedQuantity < 1) {
		return res.status(400).json({
			error: "Quantity must be a positive number",
		});
	}

	const connection = await getConnectionWithRetry();

	try {
		// Update query to modify the quantity for a specific cart item
		const [result] = await connection.query(
			`
            UPDATE cart 
            SET quantity = ? 
            WHERE user_id = ? AND product_id = ?
        `,
			[parsedQuantity, userId, productId]
		);

		// Check if any rows were actually updated
		if (result.affectedRows === 0) {
			return res.status(404).json({
				error: "Cart item not found",
			});
		}

		res.status(200).json({
			message: "Cart item quantity updated successfully",
			updatedQuantity: parsedQuantity,
		});
	} catch (err) {
		console.error("Database error:", err);
		res.status(500).json({
			error: "Database error",
			details: err.message,
		});
	} finally {
		// Always release the connection back to the pool
		connection.release();
	}
});
app.get("/api/orders/:orderId", async (req, res) => {
	const { orderId } = req.params;
	const { userId } = req.query;

	console.log("Received Order Request:", { orderId, userId });

	if (!userId || !orderId) {
		return res.status(400).json({ error: "User ID and Order ID are required" });
	}

	const connection = await getConnectionWithRetry();

	try {
		// Basic SQL query to fetch order and associated items
		const [results] = await connection.query(
			`
            SELECT 
                o.id AS order_id, 
                o.order_date, 
                o.total_amount,
                oi.product_id,
                p.name AS product_name,
                oi.quantity,
                oi.price,
                p.image AS product_image
            FROM orders o
            JOIN order_items oi ON o.id = oi.order_id
            JOIN products p ON oi.product_id = p.id
            WHERE o.id = ? AND o.user_id = ?
        `,
			[orderId, userId]
		);

		if (results.length === 0) {
			console.warn(`No order found for ID ${orderId} and User ${userId}`);
			return res.status(404).json({
				error: "Order not found",
				orderId,
				userId,
			});
		}

		// Constructing order details and items directly
		const order = results[0];
		const orderDetails = {
			id: `ORD-${order.order_id}`,
			date: new Date(order.order_date).toISOString().split("T")[0],
			total: parseFloat(order.total_amount),
			items: results.map((item) => ({
				product_id: item.product_id,
				name: item.product_name,
				quantity: item.quantity,
				price: parseFloat(item.price),
				image: item.product_image,
			})),
		};

		res.status(200).json(orderDetails);
	} catch (err) {
		console.error("Order Details Error:", {
			message: err.message,
			stack: err.stack,
			orderId,
			userId,
		});

		res.status(500).json({
			error: "Failed to retrieve order details",
			details: err.message,
			...(process.env.NODE_ENV === "development" && { stack: err.stack }),
		});
	} finally {
		// Always release the connection back to the pool
		connection.release();
	}
});
app.get("/api/orders", async (req, res) => {
	const { userId } = req.query;

	if (!userId) {
		return res.status(400).json({ error: "User ID is required" });
	}

	const connection = await getConnectionWithRetry();

	try {
		// First, get the orders
		const [orderResults] = await connection.query(
			`
            SELECT 
                o.id AS order_id, 
                o.order_date, 
                o.total_amount
            FROM orders o
            WHERE o.user_id = ?
            ORDER BY o.order_date DESC
        `,
			[userId]
		);

		// If no orders found, return empty array
		if (orderResults.length === 0) {
			return res.status(200).json([]);
		}

		// Prepare to fetch items for each order
		const orderIds = orderResults.map((order) => order.order_id);

		// Get order items for all orders in one query
		const [itemResults] = await connection.query(
			`
            SELECT 
                oi.order_id,
                oi.product_id,
                p.name,
                oi.price,
                oi.quantity,
                p.image
            FROM order_items oi
            JOIN products p ON oi.product_id = p.id
            WHERE oi.order_id IN (?)
        `,
			[orderIds]
		);

		// Group items by order
		const orderItemsMap = itemResults.reduce((acc, item) => {
			if (!acc[item.order_id]) {
				acc[item.order_id] = [];
			}
			acc[item.order_id].push({
				product_id: item.product_id,
				name: item.name,
				price: parseFloat(item.price),
				quantity: item.quantity,
				image: item.image,
			});
			return acc;
		}, {});

		// Combine orders with their items
		const processedOrders = orderResults.map((order) => ({
			id: `ORD-${order.order_id}`,
			date: new Date(order.order_date).toISOString().split("T")[0],
			total: parseFloat(order.total_amount),
			items: orderItemsMap[order.order_id] || [],
		}));

		res.status(200).json(processedOrders);
	} catch (err) {
		console.error("Orders Retrieval Error:", {
			message: err.message,
			stack: err.stack,
			userId,
		});

		res.status(500).json({
			error: "Failed to retrieve orders",
			details: err.message,
			...(process.env.NODE_ENV === "development" && { stack: err.stack }),
		});
	} finally {
		// Always release the connection back to the pool
		connection.release();
	}
});

app.post("/api/single-order", async (req, res) => {
	const { userId, productId, quantity } = req.body;

	// Validate input
	if (!userId || !productId || !quantity) {
		return res.status(400).json({
			error: "Invalid order data",
			details: "User ID, Product ID, and Quantity are required",
		});
	}

	const connection = await getConnectionWithRetry();

	try {
		// Start a database transaction
		await connection.beginTransaction();

		try {
			// First, get the product details
			const [productResults] = await connection.query(
				`
                SELECT id, name, price, image 
                FROM products 
                WHERE id = ?
            `,
				[productId]
			);

			if (productResults.length === 0) {
				throw new Error("Product not found");
			}

			const product = productResults[0];
			const totalAmount = product.price * quantity;

			// Insert order
			const [orderResult] = await connection.query(
				`
                INSERT INTO orders (user_id, order_date, total_amount) 
                VALUES (?, NOW(), ?)
            `,
				[userId, totalAmount]
			);

			const orderId = orderResult.insertId;

			// Insert order items
			await connection.query(
				`
                INSERT INTO order_items (order_id, product_id, quantity, price) 
                VALUES (?, ?, ?, ?)
            `,
				[orderId, productId, quantity, product.price]
			);

			// Commit the transaction
			await connection.commit();

			// Successfully created order
			res.status(201).json({
				id: `ORD-${orderId}`,
				userId,
				productId,
				quantity,
				totalAmount: parseFloat(totalAmount.toFixed(2)),
				orderDate: new Date().toISOString(),
				productDetails: {
					name: product.name,
					image: product.image,
				},
			});
		} catch (error) {
			// Rollback the transaction in case of any error
			await connection.rollback();
			throw error;
		}
	} catch (err) {
		console.error("Single Order Creation Error:", {
			message: err.message,
			stack: err.stack,
			userId,
			productId,
			quantity,
		});

		res.status(500).json({
			error: "Failed to create order",
			details: err.message,
			...(process.env.NODE_ENV === "development" && { stack: err.stack }),
		});
	} finally {
		// Always release the connection back to the pool
		connection.release();
	}
});
// Add Product Endpoint
app.post("/api/products/add", (req, res) => {
	try {
		const {
			name,
			category,
			description,
			fullDescription,
			price,
			imagePath,
			specifications,
		} = req.body;

		// Validate required fields
		if (!name || !category || !price) {
			return res.status(400).json({
				error:
					"Missing required fields: name, category, and price are required.",
			});
		}

		// Ensure specifications is stored as JSON or NULL
		const safeSpecifications = specifications
			? JSON.stringify(
					specifications.split("\n").filter((spec) => spec.trim() !== "")
			  )
			: null;

		// Insert query
		const insertQuery = `
			INSERT INTO products 
			(name, category, description, fullDescription, price, image, specs) 
			VALUES (?, ?, ?, ?, ?, ?, ?)
		`;

		const values = [
			name,
			category,
			description || null,
			fullDescription || null,
			price,
			imagePath || null,
			safeSpecifications,
		];

		// Execute the insert query
		connection.query(insertQuery, values, (err, result) => {
			if (err) {
				console.error("Database insertion error:", err);
				return res.status(500).json({
					error: "Failed to add product",
					details: err.message,
				});
			}

			// Respond with the newly created product ID
			res.status(201).json({
				message: "Product added successfully",
				productId: result.insertId,
			});
		});
	} catch (error) {
		console.error("Server error:", error);
		res.status(500).json({
			error: "Internal server error",
			details: error.message,
		});
	}
});
app.get("/api/products", async (req, res) => {
	// Optional query parameters for filtering and pagination
	const {
		category,
		minPrice,
		maxPrice,
		search,
		page = 1,
		limit = 20,
	} = req.query;

	const connection = await getConnectionWithRetry();

	try {
		// Construct dynamic query with optional filters
		let query = `
            SELECT 
                id, 
                name, 
                category, 
                description, 
                price, 
                image, 
                specs AS specifications
            FROM products
            WHERE 1=1
        `;

		const queryParams = [];

		// Add optional filters
		if (category) {
			query += ` AND category = ?`;
			queryParams.push(category);
		}

		if (minPrice) {
			query += ` AND price >= ?`;
			queryParams.push(parseFloat(minPrice));
		}

		if (maxPrice) {
			query += ` AND price <= ?`;
			queryParams.push(parseFloat(maxPrice));
		}

		if (search) {
			query += ` AND (name LIKE ? OR description LIKE ?)`;
			queryParams.push(`%${search}%`, `%${search}%`);
		}

		// Add pagination
		const offset = (page - 1) * limit;
		query += ` LIMIT ? OFFSET ?`;
		queryParams.push(parseInt(limit), offset);

		// Get total count for pagination
		const [countResult] = await connection.query(
			`
            SELECT COUNT(*) as total 
            FROM products 
            WHERE 1=1
            ${category ? " AND category = ?" : ""}
            ${minPrice ? " AND price >= ?" : ""}
            ${maxPrice ? " AND price <= ?" : ""}
            ${search ? " AND (name LIKE ? OR description LIKE ?)" : ""}
        `,
			queryParams.slice(0, -2)
		); // Exclude LIMIT and OFFSET

		const totalProducts = countResult[0].total;

		// Execute the query
		const [results] = await connection.query(query, queryParams);

		// Process results
		const processedResults = results.map((product) => ({
			id: product.id,
			name: product.name,
			category: product.category,
			description: product.description,
			price: parseFloat(product.price),
			image: product.image,
			specifications: product.specifications
				? safeJSONParse(product.specifications)
				: null,
		}));

		// Send response with pagination metadata
		res.json({
			products: processedResults,
			pagination: {
				total: totalProducts,
				page: parseInt(page),
				limit: parseInt(limit),
				totalPages: Math.ceil(totalProducts / limit),
			},
		});
	} catch (err) {
		console.error("Products Fetch Error:", {
			message: err.message,
			stack: err.stack,
			query: req.query,
		});

		res.status(500).json({
			error: "Failed to fetch products",
			details: err.message,
			...(process.env.NODE_ENV === "development" && { stack: err.stack }),
		});
	} finally {
		// Always release the connection back to the pool
		connection.release();
	}
});

// Safe JSON parsing utility function
function safeJSONParse(jsonString) {
	try {
		return JSON.parse(jsonString);
	} catch (error) {
		console.warn("Failed to parse JSON:", {
			input: jsonString,
			error: error.message,
		});
		return null;
	}
}
app.delete("/api/products/delete/:id", async (req, res) => {
	const productId = req.params.id;

	const connection = await getConnectionWithRetry();

	try {
		const [result] = await connection.query(
			"DELETE FROM products WHERE id = ?",
			[productId]
		);

		if (result.affectedRows === 0) {
			return res.status(404).json({ error: "Product not found" });
		}

		res.json({
			message: "Product deleted successfully",
			productId: productId,
		});
	} catch (err) {
		console.error("Error deleting product:", err);
		res.status(500).json({
			error: "Failed to delete product",
			details: err.message,
		});
	} finally {
		// Always release the connection back to the pool
		connection.release();
	}
});
app.get("/api/products/:id", async (req, res) => {
	const productId = req.params.id;

	const connection = await getConnectionWithRetry();

	try {
		const [results] = await connection.query(
			"SELECT * FROM products WHERE id = ?",
			[productId]
		);

		if (results.length === 0) {
			return res.status(404).json({ error: "Product not found" });
		}

		// Process the product (parse specifications if needed)
		const product = results[0];
		if (product.specifications) {
			try {
				product.specifications = JSON.parse(product.specifications);
			} catch (parseError) {
				console.error("Failed to parse specifications:", parseError);
				product.specifications = null;
			}
		}

		res.json(product);
	} catch (err) {
		console.error("Error fetching product:", err);
		res.status(500).json({
			error: "Failed to fetch product",
			details: err.message,
		});
	} finally {
		// Always release the connection back to the pool
		connection.release();
	}
});
app.put("/api/products/update/:id", async (req, res) => {
	const productId = req.params.id;
	const {
		name,
		category,
		description,
		fullDescription,
		price,
		imagePath,
		specifications,
	} = req.body;

	// Prepare specifications
	const safeSpecifications = specifications
		? JSON.stringify(specifications)
		: null;

	const connection = await getConnectionWithRetry();

	try {
		const query = `
            UPDATE products 
            SET 
                name = ?, 
                category = ?, 
                description = ?, 
                fullDescription = ?, 
                price = ?, 
                image = ?, 
                specs = ?
            WHERE id = ?
        `;

		const values = [
			name,
			category,
			description,
			fullDescription,
			price,
			imagePath,
			safeSpecifications,
			productId,
		];

		const [result] = await connection.query(query, values);

		if (result.affectedRows === 0) {
			return res.status(404).json({ error: "Product not found" });
		}

		res.json({
			message: "Product updated successfully",
			productId: productId,
		});
	} catch (err) {
		console.error("Error updating product:", err);
		res.status(500).json({
			error: "Failed to update product",
			details: err.message,
		});
	} finally {
		// Always release the connection back to the pool
		connection.release();
	}
});
