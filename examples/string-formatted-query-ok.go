func okDbExec(r *http.Request) {
	customerId := r.URL.Query().Get("id")
	// ok: string-formatted-query
	query := "SELECT number, expireDate, cvv FROM creditcards WHERE customerId = customerId"

	row, _ := db.Exec(query)
}
