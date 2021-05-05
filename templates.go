package main

import (
	"net/http"
	"runtime"
	"text/template"
)

var templates = map[string]*template.Template{
	"home":  template.Must(template.ParseFiles("templates/home.html")),
	"app":   template.Must(template.ParseFiles("templates/app.html")),
	"error": template.Must(template.ParseFiles("templates/error.html")),
}

type appData struct {
	FName            string
	LName            string
	Email            string
	Key              string
	NotificationType string
	Notification     string
}

type errorData struct {
	Error      string
	StackTrace string
}

func writeError(w http.ResponseWriter, err error, status int) {
	w.WriteHeader(status)

	errorData := errorData{}

	errorData.Error = err.Error()

	buf := make([]byte, 1<<16)
	stackSize := runtime.Stack(buf, false)
	stackTrace := string(buf[0:stackSize])

	errorData.StackTrace = stackTrace

	templates["error"].Execute(w, errorData)
}
