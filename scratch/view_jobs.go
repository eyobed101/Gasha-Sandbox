//go:build ignore

package main

import (
	"database/sql"
	"fmt"
	"log"

	_ "modernc.org/sqlite"
)

func main() {
	db, err := sql.Open("sqlite", "./lemas.db")
	if err != nil {
		log.Fatalf("Failed to open db: %v", err)
	}
	defer db.Close()

	rows, err := db.Query("SELECT id, file_path, status, submitted_at, completed_at FROM jobs ORDER BY submitted_at DESC LIMIT 10")
	if err != nil {
		log.Fatalf("Failed to query jobs: %v", err)
	}
	defer rows.Close()

	fmt.Println("Recent Sandbox Jobs in SQLite Database:")
	fmt.Printf("%-36s | %-40s | %-10s | %-25s\n", "Job ID", "Target File", "Status", "Submitted At")
	fmt.Println("----------------------------------------------------------------------------------------------------------------------")
	for rows.Next() {
		var id, filePath, status, submitted, completed sql.NullString
		if err := rows.Scan(&id, &filePath, &status, &submitted, &completed); err != nil {
			log.Fatalf("Row scan error: %v", err)
		}
		fmt.Printf("%-36s | %-40s | %-10s | %-25s\n", id.String, filePath.String, status.String, submitted.String)
	}
}
