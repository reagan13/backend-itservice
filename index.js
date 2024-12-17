const express = require("express");
const mysql = require("mysql2");
const app = express();
const PORT = 3000;
const bcrypt = require("bcryptjs");
const bodyParser = require("body-parser");
const cors = require("cors");
require("dotenv").config(); // Load environment variables from .env file

app.use(express.json()); // Add this to parse JSON

// const corsOptions = {
// 	origin: [
// 		"http://localhost:3000",
// 		"https://it-services-nkvo.onrender.com",
// 		"https://backend-itservices.onrender.com",
// 		"http://127.0.0.1:5500",
// 	], // Trusted origins
// 	methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
// 	allowedHeaders: ["Content-Type", "Authorization"],
// 	credentials: true,
// 	optionsSuccessStatus: 200,
// };

// // Apply CORS middleware
// app.use(cors(corsOptions));
app.use(cors());

// Parse incoming JSON requests
app.use(bodyParser.json());

// Create the MySQL connection
const connection = mysql.createConnection({
	host: process.env.DB_HOST,
	user: process.env.DB_USER,
	password: process.env.DB_PASSWORD,
	database: process.env.DB_NAME,
});

// Connect to MySQL
connection.connect((err) => {
	if (err) {
		console.error("Error connecting to MySQL:", err.stack);
		return;
	}
	console.log("Connected to MySQL as ID", connection.threadId);
});

// Start the server
app.listen(PORT, () => {
	console.log(`Server is running on port ${PORT}`);
});

// User
// signup
// Signup API Endpoint
app.post("/api/signup", (req, res) => {
	const { first_name, last_name, email, password, confirm_password } = req.body;
	console.log("Request Method:", req.method); // Should be POST

	// Basic validation
	if (!first_name || !last_name || !email || !password || !confirm_password) {
		return res.status(400).json({ error: "All fields are required" });
	}

	// Check if passwords match
	if (password !== confirm_password) {
		return res.status(400).json({ error: "Passwords do not match" });
	}

	// Check if email already exists
	const checkEmailQuery = "SELECT * FROM users WHERE email = ?";
	connection.query(checkEmailQuery, [email], (err, results) => {
		if (err) {
			return res
				.status(500)
				.json({ error: "Database error", details: err.message });
		}

		if (results.length > 0) {
			return res.status(400).json({ error: "Email already in use" });
		}

		// Hash the password before saving
		bcrypt.hash(password, 10, (err, hashedPassword) => {
			if (err) {
				return res.status(500).json({ error: "Error hashing password" });
			}

			// Insert new user into the database
			const insertQuery =
				"INSERT INTO users (first_name, last_name, email, password_hash) VALUES (?, ?, ?, ?)";

			connection.query(
				insertQuery,
				[first_name, last_name, email, hashedPassword],
				(err, results) => {
					if (err) {
						return res
							.status(500)
							.json({ error: "Error saving user", details: err.message });
					}

					res.status(201).json({
						message: "User successfully created",
						userId: results.insertId,
					});
				}
			);
		});
	});
});

// Login
// Sign-In API Endpoint
app.post("/api/signin", (req, res) => {
	console.log("Request Method:", req.method); // Should be POST
	console.log("Request Body:", req.body); // Should contain email and password
	const { email, password } = req.body;

	// Basic validation
	if (!email || !password) {
		return res.status(400).json({ error: "Email and password are required" });
	}

	// Query the database to check if the email exists
	const query = "SELECT * FROM users WHERE email = ?";
	connection.query(query, [email], (err, results) => {
		if (err) {
			return res
				.status(500)
				.json({ error: "Database error", details: err.message });
		}

		if (results.length === 0) {
			return res.status(400).json({ error: "Invalid email or password" });
		}

		// Get the user from the database (we expect only one result)
		const user = results[0];

		// Compare the entered password with the hashed password in the database
		bcrypt.compare(password, user.password_hash, (err, isMatch) => {
			if (err) {
				return res
					.status(500)
					.json({ error: "Error comparing passwords", details: err.message });
			}

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
		});
	});
});

// get all products
app.get("/api/products", (req, res) => {
	const query = "SELECT * FROM products";

	connection.query(query, (err, results) => {
		if (err) {
			console.error("Error retrieving products:", err.stack);
			return res.status(500).json({
				error: "Error retrieving products",
				details: err.message,
			});
		}

		console.log(`Retrieved ${results.length} products`);

		// Optional: Log the first product for debugging
		if (results.length > 0) {
			console.log("First Product:", results[0]);
		}

		res.json(results);
	});
});

/// In your Express backend:
app.post("/api/cart", (req, res) => {
	const { user_id, product_id, quantity } = req.body;

	// Basic validation
	if (!user_id || !product_id || !quantity) {
		return res
			.status(400)
			.json({ error: "User ID, Product ID, and Quantity are required" });
	}

	// Check if the product already exists in the cart for the given user
	const checkQuery = "SELECT * FROM cart WHERE user_id = ? AND product_id = ?";
	connection.query(checkQuery, [user_id, product_id], (err, results) => {
		if (err) {
			return res
				.status(500)
				.json({ error: "Database error", details: err.message });
		}

		if (results.length > 0) {
			// If the product already exists in the cart, add the new quantity to the existing quantity
			const newQuantity = results[0].quantity + quantity; // Increment the quantity

			const updateQuery =
				"UPDATE cart SET quantity = ? WHERE user_id = ? AND product_id = ?";
			connection.query(
				updateQuery,
				[newQuantity, user_id, product_id],
				(err, updateResults) => {
					if (err) {
						return res
							.status(500)
							.json({ error: "Error updating cart", details: err.message });
					}

					res.status(200).json({
						message: "Cart updated successfully",
						cartItem: {
							user_id,
							product_id,
							quantity: newQuantity, // Return the updated quantity
						},
					});
				}
			);
		} else {
			// If the product doesn't exist in the cart, add it with the specified quantity
			const insertQuery =
				"INSERT INTO cart (user_id, product_id, quantity) VALUES (?, ?, ?)";
			connection.query(
				insertQuery,
				[user_id, product_id, quantity],
				(err, insertResults) => {
					if (err) {
						return res
							.status(500)
							.json({ error: "Error adding to cart", details: err.message });
					}

					res.status(200).json({
						message: "Product added to cart successfully",
						cartItem: {
							user_id,
							product_id,
							quantity,
						},
					});
				}
			);
		}
	});
});

// GET Cart - Fetches the user's cart
// Cart route
app.get("/api/cart/:userId", (req, res) => {
	const userId = req.params.userId;
	"Fetching cart for user", userId;

	if (!userId) {
		return res.status(400).json({ error: "User ID is required" });
	}

	// Updated query to join with products to get full product details
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

	connection.query(query, [userId], (err, results) => {
		if (err) {
			console.error("Database error:", err);
			return res.status(500).json({
				error: "Error fetching cart",
				details: err.message,
			});
		}

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
	});
});

// Cart Update Endpoint
app.post("/api/cart/update", (req, res) => {
	const { userId, productId, quantity } = req.body;

	if (!userId || !productId || quantity === undefined) {
		return res
			.status(400)
			.json({ error: "User ID, Product ID, and Quantity are required" });
	}

	// If quantity is 0 or less, remove the item from the cart
	if (quantity <= 0) {
		const removeQuery = "DELETE FROM cart WHERE user_id = ? AND product_id = ?";
		connection.query(removeQuery, [userId, productId], (err, result) => {
			if (err) {
				return res.status(500).json({
					error: "Database error",
					details: err.message,
				});
			}

			return res.status(200).json({
				message: "Item removed from cart successfully",
			});
		});
	} else {
		// Update or insert the cart item
		const upsertQuery = `
            INSERT INTO cart (user_id, product_id, quantity) 
            VALUES (?, ?, ?) 
            ON DUPLICATE KEY UPDATE quantity = ?
        `;

		connection.query(
			upsertQuery,
			[userId, productId, quantity, quantity],
			(err, result) => {
				if (err) {
					return res.status(500).json({
						error: "Database error",
						details: err.message,
					});
				}

				res.status(200).json({
					message: "Cart updated successfully",
				});
			}
		);
	}
});

// Ensure the route matches exactly
app.delete("/api/cart/remove", (req, res) => {
	const { userId, productId } = req.body;
	"Removing item from cart", userId, productId;

	if (!userId || !productId) {
		return res
			.status(400)
			.json({ error: "User ID and Product ID are required" });
	}

	const removeQuery = "DELETE FROM cart WHERE user_id = ? AND product_id = ?";
	connection.query(removeQuery, [userId, productId], (err, result) => {
		if (err) {
			return res.status(500).json({
				error: "Database error",
				details: err.message,
			});
		}

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
	});
});

// Get Cart Details Endpoint
app.post("/api/cart/details", (req, res) => {
	const { userId, productIds } = req.body;

	if (!userId || !productIds || !Array.isArray(productIds)) {
		return res
			.status(400)
			.json({ error: "User ID and Product IDs are required" });
	}

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

	connection.query(query, [userId, productIds], (err, results) => {
		if (err) {
			return res.status(500).json({
				error: "Database error",
				details: err.message,
			});
		}

		res.status(200).json(results);
	});
});

// Place Order Endpoint
app.post("/api/orders/place", (req, res) => {
	const { userId, items } = req.body;

	if (!userId || !items || items.length === 0) {
		return res.status(400).json({ error: "User ID and items are required" });
	}

	// Start a transaction
	connection.beginTransaction((err) => {
		if (err) {
			return res.status(500).json({
				error: "Transaction start failed",
				details: err.message,
			});
		}

		// Insert order
		const orderQuery =
			"INSERT INTO orders (user_id, order_date, total_amount) VALUES (?, NOW(), ?)";

		// Calculate total amount
		const totalAmount = items.reduce((total, item) => {
			return total + item.price * item.quantity;
		}, 0);

		connection.query(orderQuery, [userId, totalAmount], (err, orderResult) => {
			if (err) {
				return connection.rollback(() => {
					res.status(500).json({
						error: "Failed to create order",
						details: err.message,
					});
				});
			}

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

			connection.query(
				orderItemsQuery,
				[orderItemsValues],
				(err, orderItemsResult) => {
					if (err) {
						return connection.rollback(() => {
							res.status(500).json({
								error: "Failed to add order items",
								details: err.message,
							});
						});
					}

					// Remove items from cart
					const removeCartQuery = "DELETE FROM cart WHERE user_id = ?";
					connection.query(removeCartQuery, [userId], (err, removeResult) => {
						if (err) {
							return connection.rollback(() => {
								res.status(500).json({
									error: "Failed to clear cart",
									details: err.message,
								});
							});
						}

						// Commit the transaction
						connection.commit((err) => {
							if (err) {
								return connection.rollback(() => {
									res.status(500).json({
										error: "Transaction commit failed",
										details: err.message,
									});
								});
							}

							res.status(200).json({
								message: "Order placed successfully",
								orderId: orderId,
							});
						});
					});
				}
			);
		});
	});
});

// Get User Orders Endpoint
app.get("/api/orders", (req, res) => {
	const { userId } = req.query;

	if (!userId) {
		return res.status(400).json({ error: "User ID is required" });
	}

	// First, get the orders
	const ordersQuery = `
        SELECT 
            o.id AS order_id, 
            o.order_date, 
            o.total_amount
        FROM orders o
        WHERE o.user_id = ?
        ORDER BY o.order_date DESC
    `;

	connection.query(ordersQuery, [userId], (err, orderResults) => {
		if (err) {
			console.error("Orders Query Error:", err);
			return res.status(500).json({
				error: "Failed to retrieve orders",
				details: err.message,
			});
		}

		// If no orders found, return empty array
		if (orderResults.length === 0) {
			return res.status(200).json([]);
		}

		// Prepare to fetch items for each order
		const orderIds = orderResults.map((order) => order.order_id);

		// Get order items for all orders in one query
		const itemsQuery = `
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
        `;

		connection.query(itemsQuery, [orderIds], (itemErr, itemResults) => {
			if (itemErr) {
				console.error("Items Query Error:", itemErr);
				return res.status(500).json({
					error: "Failed to retrieve order items",
					details: itemErr.message,
				});
			}

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
		});
	});
});

// Single Order Details Endpoint
app.get("/api/orders/:orderId", (req, res) => {
	const { orderId } = req.params;
	const { userId } = req.query;

	if (!userId || !orderId) {
		return res.status(400).json({ error: "User ID and Order ID are required" });
	}

	// Extract numeric ID from formatted order ID
	const numericOrderId = orderId.replace("ORD-", "");

	// First, get the order details
	const orderQuery = `
        SELECT 
            o.id AS order_id, 
            o.order_date, 
            o.total_amount
        FROM orders o
        WHERE o.id = ? AND o.user_id = ?
    `;

	connection.query(
		orderQuery,
		[numericOrderId, userId],
		(err, orderResults) => {
			if (err) {
				console.error("Order Query Error:", err);
				return res.status(500).json({
					error: "Failed to retrieve order details",
					details: err.message,
				});
			}

			if (orderResults.length === 0) {
				return res.status(404).json({ error: "Order not found" });
			}

			// Get order items
			const itemsQuery = `
            SELECT 
                oi.product_id,
                p.name,
                oi.price,
                oi.quantity,
                p.image
            FROM order_items oi
            JOIN products p ON oi.product_id = p.id
            WHERE oi.order_id = ?
        `;

			connection.query(itemsQuery, [numericOrderId], (itemErr, itemResults) => {
				if (itemErr) {
					console.error("Items Query Error:", itemErr);
					return res.status(500).json({
						error: "Failed to retrieve order items",
						details: itemErr.message,
					});
				}

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
			});
		}
	);
});

app.put("/api/cart/update-quantity", (req, res) => {
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

	// Update query to modify the quantity for a specific cart item
	const updateQuery = `
        UPDATE cart 
        SET quantity = ? 
        WHERE user_id = ? AND product_id = ?
    `;

	connection.query(
		updateQuery,
		[parsedQuantity, userId, productId],
		(err, result) => {
			if (err) {
				return res.status(500).json({
					error: "Database error",
					details: err.message,
				});
			}

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
		}
	);
});

// Get Single Order Details

app.get("/api/orders/:orderId", (req, res) => {
	const { orderId } = req.params;
	const { userId } = req.query;

	"Received Order Request:", { orderId, userId };

	if (!userId || !orderId) {
		return res.status(400).json({ error: "User ID and Order ID are required" });
	}

	// Basic SQL query to fetch order and associated items
	const query = `
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
    `;

	connection.query(query, [orderId, userId], (err, results) => {
		if (err) {
			console.error("Database Error:", err);
			return res.status(500).json({
				error: "Failed to retrieve order details",
				details: err.message,
				stack: err.stack,
			});
		}

		if (results.length === 0) {
			console.warn(`No order found for ID ${orderId} and User ${userId}`);
			return res.status(404).json({
				error: "Order not found",
				orderId,
				userId,
			});
		}

		try {
			// Constructing order details and items directly
			const order = results[0];
			const orderDetails = {
				order_id: order.order_id,
				order_date: new Date(order.order_date).toISOString(),
				total_amount: order.total_amount,
				items: results.map((item) => ({
					product_id: item.product_id,
					product_name: item.product_name,
					quantity: item.quantity,
					price: item.price,
					product_image: item.product_image,
				})),
			};

			res.status(200).json(orderDetails);
		} catch (parseError) {
			console.error("Parsing Error:", parseError);
			res.status(500).json({
				error: "Failed to parse order details",
				details: parseError.message,
			});
		}
	});
});

app.get("/api/orders", (req, res) => {
	const { userId } = req.query;

	if (!userId) {
		return res.status(400).json({ error: "User ID is required" });
	}

	// First, get the orders
	const ordersQuery = `
        SELECT 
            o.id AS order_id, 
            o.order_date, 
            o.total_amount
        FROM orders o
        WHERE o.user_id = ?
        ORDER BY o.order_date DESC
    `;

	connection.query(ordersQuery, [userId], (err, orderResults) => {
		if (err) {
			console.error("Database Error:", err);
			return res.status(500).json({
				error: "Failed to retrieve orders",
				details: err.message,
			});
		}

		// If no orders found, return empty array
		if (orderResults.length === 0) {
			return res.status(200).json([]);
		}

		// Prepare to fetch items for each order
		const orderIds = orderResults.map((order) => order.order_id);

		// Get order items for all orders in one query
		const itemsQuery = `
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
        `;

		connection.query(itemsQuery, [orderIds], (itemErr, itemResults) => {
			if (itemErr) {
				console.error("Items Fetch Error:", itemErr);
				return res.status(500).json({
					error: "Failed to retrieve order items",
					details: itemErr.message,
				});
			}

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
		});
	});
});

// Single Product Direct Purchase Endpoint
app.post("/api/single-order", (req, res) => {
	const { userId, productId, quantity } = req.body;

	// Validate input
	if (!userId || !productId || !quantity) {
		return res.status(400).json({
			error: "Invalid order data",
			details: "User ID, Product ID, and Quantity are required",
		});
	}

	// Start a database transaction
	connection.beginTransaction((transactionError) => {
		if (transactionError) {
			console.error("Transaction Start Error:", transactionError);
			return res.status(500).json({
				error: "Transaction initialization failed",
				details: transactionError.message,
			});
		}

		// First, get the product details
		const productQuery = `
            SELECT id, name, price, image 
            FROM products 
            WHERE id = ?
        `;

		connection.query(
			productQuery,
			[productId],
			(productErr, productResults) => {
				if (productErr || productResults.length === 0) {
					console.error("Product Fetch Error:", productErr);
					return connection.rollback(() => {
						res.status(404).json({
							error: "Product not found",
							details: productErr?.message,
						});
					});
				}

				const product = productResults[0];
				const totalAmount = product.price * quantity;

				// Insert order
				const orderQuery = `
                INSERT INTO orders (user_id, order_date, total_amount) 
                VALUES (?, NOW(), ?)
            `;

				connection.query(
					orderQuery,
					[userId, totalAmount],
					(orderErr, orderResult) => {
						if (orderErr) {
							console.error("Order Insert Error:", orderErr);
							return connection.rollback(() => {
								res.status(500).json({
									error: "Failed to create order",
									details: orderErr.message,
								});
							});
						}

						const orderId = orderResult.insertId;

						// Insert order items
						const itemQuery = `
                    INSERT INTO order_items (order_id, product_id, quantity, price) 
                    VALUES (?, ?, ?, ?)
                `;

						connection.query(
							itemQuery,
							[orderId, productId, quantity, product.price],
							(itemErr, itemResult) => {
								if (itemErr) {
									console.error("Order Item Insert Error:", itemErr);
									return connection.rollback(() => {
										res.status(500).json({
											error: "Failed to add order item",
											details: itemErr.message,
										});
									});
								}

								// Commit the transaction
								connection.commit((commitErr) => {
									if (commitErr) {
										console.error("Transaction Commit Error:", commitErr);
										return connection.rollback(() => {
											res.status(500).json({
												error: "Transaction commit failed",
												details: commitErr.message,
											});
										});
									}

									// Successfully created order
									res.status(201).json({
										id: `ORD-${orderId}`,
										userId,
										productId,
										quantity,
										totalAmount,
										orderDate: new Date().toISOString(),
										productDetails: {
											name: product.name,
											image: product.image,
										},
									});
								});
							}
						);
					}
				);
			}
		);
	});
});

//  add product
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

// GET all products
app.get("/api/products", (req, res) => {
	const query = "SELECT * FROM products";

	connection.query(query, (err, results) => {
		if (err) {
			console.error("Error fetching products:", err);
			return res.status(500).json({
				error: "Failed to fetch products",
				details: err.message,
			});
		}

		// Parse specifications if they're stored as JSON
		const processedResults = results.map((product) => ({
			...product,
			specifications: product.specifications
				? JSON.parse(product.specifications)
				: null,
		}));

		res.json(processedResults);
	});
});

// DELETE product route
app.delete("/api/products/delete/:id", (req, res) => {
	const productId = req.params.id;

	const query = "DELETE FROM products WHERE id = ?";

	connection.query(query, [productId], (err, result) => {
		if (err) {
			console.error("Error deleting product:", err);
			return res.status(500).json({
				error: "Failed to delete product",
				details: err.message,
			});
		}

		if (result.affectedRows === 0) {
			return res.status(404).json({ error: "Product not found" });
		}

		res.json({
			message: "Product deleted successfully",
			productId: productId,
		});
	});
});

// GET single product by ID
app.get("/api/products/:id", (req, res) => {
	const productId = req.params.id;

	const query = "SELECT * FROM products WHERE id = ?";

	connection.query(query, [productId], (err, results) => {
		if (err) {
			console.error("Error fetching product:", err);
			return res.status(500).json({
				error: "Failed to fetch product",
				details: err.message,
			});
		}

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
	});
});

// UPDATE product route
app.put("/api/products/update/:id", (req, res) => {
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

	connection.query(query, values, (err, result) => {
		if (err) {
			console.error("Error updating product:", err);
			return res.status(500).json({
				error: "Failed to update product",
				details: err.message,
			});
		}

		if (result.affectedRows === 0) {
			return res.status(404).json({ error: "Product not found" });
		}

		res.json({
			message: "Product updated successfully",
			productId: productId,
		});
	});
});
