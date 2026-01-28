package database

func (db *Database) Getint(detail, username string) (int, error) {
	var result int
	query := "SELECT " + detail + " FROM `users` WHERE username = ?"
	err := db.db.QueryRow(query, username).Scan(&result)
	if err != nil {
		return 0, err
	}
	return result, nil
}
