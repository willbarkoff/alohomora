package main

import (
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/crewjam/saml/samlsp"
	"github.com/julienschmidt/httprouter"
	"github.com/tv42/zbase32"
)

func writeApp(w http.ResponseWriter, r *http.Request, nottype string, notcontent string) {
	fname := samlsp.AttributeFromContext(r.Context(), "fname")
	lname := samlsp.AttributeFromContext(r.Context(), "lname")
	email := samlsp.AttributeFromContext(r.Context(), "email")

	key, keyErr := os.ReadFile("hu/" + domainFromEmail(email) + "/" + hashFromEmail(email))
	if key == nil || keyErr != nil {
		key = []byte("No key available")
	}

	if nottype == "" {
		nottype = "is-hidden"
	}

	templates["app"].Execute(w, appData{fname, lname, email, string(key), nottype, notcontent})

}

func app(w http.ResponseWriter, r *http.Request) {
	writeApp(w, r, "", "")
}

func uploadKey(w http.ResponseWriter, r *http.Request) {
	email := samlsp.AttributeFromContext(r.Context(), "email")
	filename := "hu/" + domainFromEmail(email) + "/" + hashFromEmail(email)

	_ = os.Mkdir("hu/"+domainFromEmail(email), 0700)

	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}

	err = file.Truncate(0)
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}

	newKey, _, err := r.FormFile("new-key")
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}

	_, err = io.Copy(file, newKey)
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}

	writeApp(w, r, "is-success", "Your key has been uploaded.")
}

func deleteKey(w http.ResponseWriter, r *http.Request) {
	email := samlsp.AttributeFromContext(r.Context(), "email")
	filename := "hu/" + domainFromEmail(email) + "/" + hashFromEmail(email)

	err := os.Remove(filename)
	if os.IsNotExist(err) {
		writeApp(w, r, "is-warning", "You don't have a key, so we can't delete it.")
		return
	} else if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}

	writeApp(w, r, "is-success", "Your key has been deleted.")
}

func home(w http.ResponseWriter, r *http.Request) {
	// samlsp.
	if samlsp.AttributeFromContext(r.Context(), "email") != "" {
		http.Redirect(w, r, "/app", http.StatusTemporaryRedirect)
		return
	}

	templates["home"].Execute(w, nil)
}

//TODO: There's probably a better way
func logout(samlSP *samlsp.Middleware) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := samlSP.Session.DeleteSession(w, r)
		if err != nil {
			writeError(w, err, http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	})
}

func domainFromEmail(email string) string {
	split := strings.Split(email, "@")
	if len(split) < 2 {
		return ""
	}
	return strings.Split(email, "@")[1]
}

func hashFromEmail(email string) string {
	user := strings.Split(email, "@")[0]
	shasum := [sha1.Size]byte(sha1.Sum([]byte(user)))
	return zbase32.EncodeToString(shasum[:])
}

func serveFile(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	file, err := os.ReadFile("./hu/" + p.ByName("filepath"))
	if os.IsNotExist(err) {
		writeError(w, errors.New("Page not found"), http.StatusInternalServerError)
		return
	} else if err != nil {
		writeError(w, err, http.StatusInternalServerError)
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	w.WriteHeader(http.StatusOK)
	w.Write(file)
}

func main() {
	keyPair, err := tls.LoadX509KeyPair("service.cert", "service.key")
	if err != nil {
		panic(err) // TODO handle error
	}
	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		panic(err) // TODO handle error
	}

	metadata, err := os.ReadFile("./metadata.xml")
	if err != nil {
		panic(err)
	}

	idpMetadata, err := samlsp.ParseMetadata(metadata)
	if err != nil {
		panic(err) // TODO handle error
	}

	rootURL, err := url.Parse(os.Args[1])
	if err != nil {
		panic(err) // TODO handle error
	}

	samlSP, _ := samlsp.New(samlsp.Options{
		URL:         *rootURL,
		Key:         keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate: keyPair.Leaf,
		IDPMetadata: idpMetadata,
		EntityID:    os.Args[1],
	})

	r := httprouter.New()

	r.NotFound = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeError(w, errors.New("Page not found"), http.StatusInternalServerError)
		return
	})

	r.MethodNotAllowed = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeError(w, errors.New("Method not allowed"), http.StatusInternalServerError)
		return
	})

	r.PanicHandler = func(w http.ResponseWriter, r *http.Request, i interface{}) {
		writeError(w, i.(error), http.StatusInternalServerError)
		return
	}

	r.Handler("GET", "/", http.HandlerFunc(home))
	r.Handler("POST", "/", http.HandlerFunc(home))
	r.Handler("GET", "/app", samlSP.RequireAccount(http.HandlerFunc(app)))
	r.Handler("POST", "/upload", samlSP.RequireAccount(http.HandlerFunc(uploadKey)))
	r.Handler("POST", "/delete", samlSP.RequireAccount(http.HandlerFunc(deleteKey)))
	r.Handler("POST", "/logout", samlSP.RequireAccount(logout(samlSP)))
	r.Handle("GET", "/.well_known/openpgpkey/hu/*filepath", serveFile)
	r.Handler("POST", "/saml/:saml_endpoint", samlSP)

	http.ListenAndServe(":5309", r)
}
