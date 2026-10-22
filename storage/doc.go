// Package storage persists scans and findings. It provides an in-memory ring
// buffer backend for the hot path and a pure-Go SQLite backend for durability.
package storage
