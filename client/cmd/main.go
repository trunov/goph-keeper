package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/gdamore/tcell/v2"
	"github.com/google/uuid"
	"github.com/rivo/tview"
	log "github.com/sirupsen/logrus"
	"github.com/trunov/goph-keeper/client/internal/encryption"
	"github.com/trunov/goph-keeper/client/internal/http"
)

var errCustom = errors.New("file is found, but there are no words in it")
var credManager = &http.CredentialManager{}
var encryptor *encryption.Encryptor

func init() {
	l := log.New()

	l.SetFormatter(&log.JSONFormatter{})

	file, err := os.OpenFile("logrus.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Info("Failed to log to file, using default stderr")
	} else {
		log.SetOutput(file)
	}

	l.SetLevel(log.InfoLevel)
}

func handleRegistration(hc *http.Client, email, password string, callback func(error)) {
	req := http.RegRequest{
		Email:    email,
		Password: password,
	}

	_, err := hc.Register(req)
	callback(err)
}

func handleLogin(hc *http.Client, email, password string, onSuccess func(token string), onFailure func(error)) {
	req := http.LoginRequest{
		Email:    email,
		Password: password,
	}

	resp, err := hc.Login(req)
	if err != nil {
		log.Error("error: ", err.Error())
		// Handle HTTP request errors
		onFailure(err)
		return
	}

	if resp.StatusCode() != 200 {
		log.Error("error: ", string(resp.Body()))
		onFailure(errors.New(string(resp.Body())))
		return
	}

	token := string(resp.Body())

	// Verify the token is not empty as a basic check
	if token == "" {
		log.Info("token: ", token)
		onFailure(fmt.Errorf("empty token received"))
		return
	}

	// Call onSuccess with the JWT token if login is successful
	onSuccess(token)
}

func handleSaveCredential(hc *http.Client, dataType, metaInfo string, binaryData []byte, onSuccess func(), onFailure func(error)) {
	req := http.StoreRequest{
		DataType:   dataType,
		BinaryData: binaryData,
		MetaInfo:   metaInfo,
		ClientID:   hc.ClientID,
	}

	resp, err := hc.Store(req)
	if err != nil {
		log.Println("error: ", err.Error())
		onFailure(err)
		return
	}

	if resp.StatusCode() != 200 {
		log.Println("error: ", string(resp.Body()))
		errorMessage := string(resp.Body())
		if resp.StatusCode() == 401 {
			onFailure(errors.New("Unauthorized"))
		} else {
			onFailure(errors.New(errorMessage))
		}
		return
	}

	onSuccess()
}

func showRegistrationForm(app *tview.Application, hc *http.Client) {
	registrationForm := tview.NewForm()

	registrationForm.
		AddInputField("Email", "", 64, nil, nil).
		AddPasswordField("Password", "", 64, '*', nil).
		AddButton("Register", func() {
			email := registrationForm.GetFormItemByLabel("Email").(*tview.InputField).GetText()
			password := registrationForm.GetFormItemByLabel("Password").(*tview.InputField).GetText()

			handleRegistration(hc, email, password, func(err error) {
				if err != nil {
					log.Printf("Registration error: %v", err)
				} else {
					showLoginForm(app, hc)
				}
			})
		}).
		AddButton("Back", func() {
			showLoginForm(app, hc)
		})

	registrationForm.SetBorder(true).SetTitle("Register Your Account").SetTitleAlign(tview.AlignLeft)
	app.SetRoot(registrationForm, true)
}

func saveCredentials(app *tview.Application, hc *http.Client) {
	saveCredentialsForm := tview.NewForm()

	dataTypeOptions := []string{
		"Login/Password",
		"Text data",
		"Binary data",
		"Bank card",
	}

	var selectedDataType string
	saveCredentialsForm.AddDropDown("DataType", dataTypeOptions, 0, func(option string, index int) {
		selectedDataType = option
	})

	saveCredentialsForm.
		AddInputField("BinaryData", "", 64, nil, nil).
		AddInputField("MetaInfo", "", 64, nil, nil).
		AddButton("Save", func() {
			dataType := selectedDataType
			binaryData := saveCredentialsForm.GetFormItemByLabel("BinaryData").(*tview.InputField).GetText()
			metaInfo := saveCredentialsForm.GetFormItemByLabel("MetaInfo").(*tview.InputField).GetText()
			encryptedBinaryData, _ := encryptor.Encrypt([]byte(binaryData))

			handleSaveCredential(hc, dataType, metaInfo, encryptedBinaryData, func() {
				showCredentialsForm(app, hc)
			}, func(err error) {
				modal := tview.NewModal()
				if err.Error() == "Unauthorized" {
					modal.
						SetText("Session is expired, please login again").
						AddButtons([]string{"OK"}).
						SetDoneFunc(func(buttonIndex int, buttonLabel string) {
							app.SetRoot(modal, false)
							showLoginForm(app, hc)
						})
				} else {
					modal.
						SetText(fmt.Sprintf("Saving credentials failed: %v", err)).
						AddButtons([]string{"Try again"}).
						SetDoneFunc(func(buttonIndex int, buttonLabel string) {
							app.SetRoot(modal, false)

							app.SetRoot(saveCredentialsForm, true)
						})

					log.Error("Error saving credentials:", err)
				}
				app.SetRoot(modal, true)
			})
		}).
		AddButton("Back", func() {
			showCredentialsForm(app, hc)
		})

	saveCredentialsForm.SetBorder(true).SetTitle("Save credentials").SetTitleAlign(tview.AlignLeft)
	app.SetRoot(saveCredentialsForm, true)
}

func readBip39Words() (string, error) {
	file, err := os.ReadFile("words.txt")
	if err != nil {
		return "", err
	}

	if len(file) == 0 {
		return "", errCustom
	}

	return string(file), nil
}

func showCredentialsForm(app *tview.Application, hc *http.Client) {
	credentialsForm := tview.NewForm()

	words, err := readBip39Words()
	if err != nil {
		errorText := "Error: 'words.txt' file not found. Please create a 'words.txt' file with your mnemonic words to proceed."
		if errors.Is(err, errCustom) {
			errorText = "Error: 'words.txt' file was found, but it present as empty. Please insert your mnemonic words to proceed."
		}

		// Display an error message and a "Try Again" button if words.txt is not found
		modal := tview.NewModal().
			SetText(errorText).
			AddButtons([]string{"Try Again", "Quit"}).
			SetDoneFunc(func(buttonIndex int, buttonLabel string) {
				if buttonLabel == "Try Again" {
					showCredentialsForm(app, hc) // Recursively call to refresh the form
				} else if buttonLabel == "Quit" {
					hc.ShutdownWS()
					app.Stop()
				}
			})

		app.SetRoot(modal, false)
	} else {
		encryptor = encryption.NewEncryptor(words)

		credentialsForm.
			AddButton("Show Credentials", func() {
				showCredentials(app, hc, credentialsForm)
			}).
			AddButton("Save Credential", func() {
				saveCredentials(app, hc)
			}).
			AddButton("Quit", func() {
				hc.ShutdownWS()
				app.Stop()
			})

		credentialsForm.SetBorder(true).SetTitle("Credentials Options").SetTitleAlign(tview.AlignLeft)
		app.SetRoot(credentialsForm, true)

		go hc.ConnectToWebSocket()
	}
}

func showCredentials(app *tview.Application, hc *http.Client, returnToForm tview.Primitive) {
	creds, err := hc.RetrieveCredentials()
	if err != nil {
		log.Println("error: ", err.Error())
		return
	}

	textView := tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(true).
		SetWrap(true).
		SetTextAlign(tview.AlignLeft).
		SetDoneFunc(func(key tcell.Key) {
			if key == tcell.KeyEscape {
				app.SetRoot(returnToForm, true)
			}
		})

	// Update the global CredentialManager instance
	credManager.App = app
	credManager.TextView = textView

	// Set the fetched credentials and update the display
	credManager.SetCredentials(creds)
	for _, cred := range credManager.Credentials {
		decryptedBinaryData, err := encryptor.Decrypt(cred.BinaryData)
		log.Error(err)

		fmt.Fprintf(textView, "DataType: %d\nBinaryData: %s\nMetaInfo: %s\n\n", cred.DataType, string(decryptedBinaryData), cred.MetaInfo)
	}

	instruction := "Press Esc to return\n\n"
	textView.SetText(instruction + textView.GetText(true))

	app.SetRoot(textView, true).SetFocus(textView)
}

func showLoginForm(app *tview.Application, hc *http.Client) {
	loginForm := tview.NewForm()

	loginForm.
		AddInputField("Email", "", 64, nil, nil).
		AddPasswordField("Password", "", 64, '*', nil).
		AddButton("Login", func() {
			email := loginForm.GetFormItemByLabel("Email").(*tview.InputField).GetText()
			password := loginForm.GetFormItemByLabel("Password").(*tview.InputField).GetText()

			handleLogin(hc, email, password,
				func(token string) { // onSuccess callback now includes the token
					hc.JWTToken = token
					showCredentialsForm(app, hc)
				},
				func(err error) { // onFailure callback handles errors
					log.Printf("Login error: %v", err)

					modal := tview.NewModal()
					modal.
						SetText(fmt.Sprintf("Login failed: %v", err)).
						AddButtons([]string{"OK"}).
						SetDoneFunc(func(buttonIndex int, buttonLabel string) {
							app.SetRoot(modal, false)

							app.SetRoot(loginForm, true)
						})

					app.SetRoot(modal, true)

				})
		}).
		AddButton("Register", func() {
			showRegistrationForm(app, hc)
		}).
		AddButton("Quit", func() {
			hc.ShutdownWS()
			app.Stop()
		})

	loginForm.SetBorder(true).SetTitle("Login to Your Account").SetTitleAlign(tview.AlignLeft)
	app.SetRoot(loginForm, true)
}

func fetchVersionAndUpdateFooter(hc *http.Client, footer *tview.TextView, app *tview.Application) {
	version, err := hc.FetchVersion()
	if err != nil {
		app.QueueUpdateDraw(func() {
			footer.SetText(fmt.Sprintf("Failed to fetch version: %v", err))
		})
		return
	}

	app.QueueUpdateDraw(func() {
		footer.SetText(fmt.Sprintf("Version %s", version))
	})
}

// could be taken out to utils package
func GenerateUniqueID() string {
	return uuid.New().String()
}

func main() {
	app := tview.NewApplication()

	// needed for WS so broadcast does not go to person who makes endpoint call
	clientID := GenerateUniqueID()
	hc := http.NewClient("http://localhost:3000/api/v1", credManager, clientID)

	initialForm := tview.NewForm().
		AddButton("Login", func() {
			showLoginForm(app, hc)
		}).
		AddButton("Register", func() {
			showRegistrationForm(app, hc)
		}).
		AddButton("Quit", func() {
			app.Stop()
		})
	initialForm.SetBorder(true).SetTitle("Welcome! Please Login or Register.").SetTitleAlign(tview.AlignLeft)

	versionFooter := tview.NewTextView().
		SetText("Fetching version...").
		SetTextAlign(tview.AlignCenter).
		SetDynamicColors(true)

	layout := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(initialForm, 0, 1, true).
		AddItem(versionFooter, 1, 0, false)

	go fetchVersionAndUpdateFooter(hc, versionFooter, app)

	if err := app.SetRoot(layout, true).EnableMouse(true).Run(); err != nil {
		panic(err)
	}
}
