func dbQuery5(r *http.Request, username string, password string) {
	// ruleid: string-formatted-query
	query := fmt.Sprintf("INSERT into users (username, password) VALUES(%s, %s)", username, password)
	_, err = db.QueryRow(query)
	if err != nil {
		http.Error("mistake")
	}
}
