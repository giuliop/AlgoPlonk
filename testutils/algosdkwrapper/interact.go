package algosdkwrapper

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/algorand/go-algorand-sdk/v2/abi"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// DeployArc4AppIfNeeded lookups the appName among the apps deployed in the local
// network by the main account. If the app is not found, it deploys it.
// If found, it checks that the app is up to date with the latest compiled version
// and if not it deletes it and deploys the new version.
// To look for the app, it uses the func `GetAppByName` which looks for a global state
// field `app_name' with value appName.
//
// The function expects to find the files:
// - dir + appName + ".approval.teal"
// - dir + appName + ".clear.teal"
// - dir + appName + ".arc32.json"
//
// A local network must be running
func DeployArc4AppIfNeeded(appName string, dir string) (
	appId uint64, err error) {

	algodClient := GetAlgodClient()

	approvalBin, err := CompileTealFromFile(filepath.Join(dir,
		appName+".approval.teal"))
	if err != nil {
		return 0, fmt.Errorf("failed to read approval program: %v", err)
	}
	clearBin, err := CompileTealFromFile(filepath.Join(dir,
		appName+".clear.teal"))
	if err != nil {
		return 0, fmt.Errorf("failed to read clear program: %v", err)
	}
	schema, err := ReadArc32Schema(filepath.Join(dir, appName+".arc32.json"))
	if err != nil {
		return 0, fmt.Errorf("failed to read arc32 schema: %v", err)
	}

	creator, err := GetDefaultAccount()
	if err != nil {
		return 0, fmt.Errorf("failed to get localnet default account: %v", err)
	}

	app, err := GetAppByName(appName, creator.Address.String())
	if err != nil {
		return 0, fmt.Errorf("failed to read the blockchain: %v", err)
	}
	// if app exists and is up to date, return its id, otherwise delete it
	if app != nil {
		onchainApproval := app.Params.ApprovalProgram
		onchainClear := app.Params.ClearStateProgram
		if bytes.Equal(onchainApproval, approvalBin) &&
			bytes.Equal(onchainClear, clearBin) {
			fmt.Printf("App %s already exists with id %d and is up to date\n",
				appName, app.Id)
			return app.Id, nil
		} else {
			fmt.Printf("App %s exists but has been modified, deleting it...\n",
				appName)
			sp, err := algodClient.SuggestedParams().Do(context.Background())
			if err != nil {
				return 0, fmt.Errorf("failed to get suggested params : %v", err)
			}
			deleteMethod, err := schema.Contract.GetMethodByName("update")
			if err != nil {
				return 0, fmt.Errorf("failed to get update method: %v", err)
			}
			txn, err := transaction.MakeApplicationDeleteTx(
				app.Id, [][]byte{deleteMethod.GetSelector()}, nil, nil, nil, sp,
				creator.Address, nil, types.Digest{}, [32]byte{}, types.ZeroAddress,
			)
			if err != nil {
				return 0, fmt.Errorf("failed to make delete txn: %v", err)
			}
			_, err = SendTxn(txn, creator)
			if err != nil {
				return 0, fmt.Errorf("error sending delete transaction:  %v", err)
			}
		}
	}

	// create app
	sp, err := algodClient.SuggestedParams().Do(context.Background())
	if err != nil {
		return 0, fmt.Errorf("failed to get suggested params: %v", err)
	}
	createMethod, err := schema.Contract.GetMethodByName("create")
	if err != nil {
		return 0, fmt.Errorf("failed to get create method: %v", err)
	}
	extraPages := uint32(len(approvalBin)) / 2048
	if extraPages > 3 {
		return 0, fmt.Errorf("approval program too large even for extra pages: "+
			"%d bytes", len(approvalBin))
	}
	txn, err := transaction.MakeApplicationCreateTxWithExtraPages(
		false, approvalBin, clearBin,
		types.StateSchema{NumUint: schema.State.Global.NumUints,
			NumByteSlice: schema.State.Global.NumByteSlices},
		types.StateSchema{NumUint: schema.State.Local.NumUints,
			NumByteSlice: schema.State.Local.NumByteSlices},
		[][]byte{createMethod.GetSelector(), []byte(appName)},
		nil, nil, nil,
		sp, creator.Address, nil,
		types.Digest{}, [32]byte{}, types.ZeroAddress, extraPages,
	)
	if err != nil {
		return 0, fmt.Errorf("failed to make create txn: %v", err)
	}
	confirmedTxn, err := SendTxn(txn, creator)
	if err != nil {
		return 0, fmt.Errorf("error sending create transaction:  %v", err)
	}
	fmt.Printf("App %s created with id %d\n", appName,
		confirmedTxn.ApplicationIndex)
	return confirmedTxn.ApplicationIndex, nil
}

// Arc32Schema defines a partial ARC32 schema
type Arc32Schema struct {
	Source struct {
		Approval string `json:"approval"`
		Clear    string `json:"clear"`
	} `json:"source"`
	State struct {
		Global struct {
			NumByteSlices uint64 `json:"num_byte_slices"`
			NumUints      uint64 `json:"num_uints"`
		} `json:"global"`
		Local struct {
			NumByteSlices uint64 `json:"num_byte_slices"`
			NumUints      uint64 `json:"num_uints"`
		} `json:"local"`
	} `json:"state"`
	Contract abi.Contract `json:"contract"`
}

// ReadArc32Schema reads an ARC32 schema from a JSON file
func ReadArc32Schema(filepath string) (
	schema *Arc32Schema, err error) {

	file, err := os.Open(filepath)
	if err != nil {
		return schema, fmt.Errorf("error opening schema file: %v", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	if err = decoder.Decode(&schema); err != nil {
		return schema, fmt.Errorf("error decoding schema file: %v", err)
	}

	return schema, nil
}

// CompileTealFromFile reads a teal file and returns a compiled b64 binary.
// A local network must be running
func CompileTealFromFile(tealFile string) ([]byte, error) {
	algodClient := GetAlgodClient()

	teal, err := os.ReadFile(tealFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s from file: %v", tealFile, err)
	}

	result, err := algodClient.TealCompile(teal).Do(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to compile %s: %v", tealFile, err)
	}
	binary, err := base64.StdEncoding.DecodeString(result.Result)
	if err != nil {
		log.Fatalf("failed to decode approval program: %v", err)
	}

	return binary, nil
}

// SendTxn signs and sends a transaction to the network.
// If no account is provided, it uses the default localnet account.
// A local network must be running
func SendTxn(txn types.Transaction, account *crypto.Account) (
	*models.PendingTransactionInfoResponse, error) {
	algodClient := GetAlgodClient()
	var err error
	if account == nil {
		account, err = GetDefaultAccount()
		if err != nil {
			return nil, fmt.Errorf("failed to get localnet default account: %s",
				err)
		}
	}

	txid, stx, err := crypto.SignTransaction(account.PrivateKey, txn)
	if err != nil {
		return nil, fmt.Errorf("failed to sign transaction: %v", err)
	}
	_, err = algodClient.SendRawTransaction(stx).Do(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to send transaction: %v", err)
	}
	confirmedTxn, err := transaction.WaitForConfirmation(algodClient, txid,
		4, context.Background())
	if err != nil {
		return nil, fmt.Errorf("error waiting for confirmation:  %v", err)
	}
	return &confirmedTxn, nil
}

// GetAppByName returns the the first app it finds that is created by creatorAddress
// and has a global storage field `app_name' with value appName.
// If the app is not found, it returns nil.
// A local network must be running
func GetAppByName(appName string, creatorAddress string) (
	*models.Application, error) {
	algodClient := GetAlgodClient()
	appsByCreator, err := algodClient.AccountInformation(creatorAddress).Do(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get account information: %v", err)
	}
	for _, app := range appsByCreator.CreatedApps {
		for _, global := range app.Params.GlobalState {
			key, _ := base64.StdEncoding.DecodeString(global.Key)
			value, _ := base64.StdEncoding.DecodeString(global.Value.Bytes)
			if bytes.Equal(key, []byte("app_name")) &&
				bytes.Equal(value, []byte(appName)) {
				return &app, nil
			}
		}
	}
	return nil, nil
}

// BuildMethodCallParams builds the parameters to add a method call to
// an atomic transaction composer.
func BuildMethodCallParams(
	appId uint64, schema *Arc32Schema,
	methodName string, oc types.OnCompletion,
	methodArgs []interface{}, boxes []types.AppBoxReference,
	signer transaction.TransactionSigner,
) (*transaction.AddMethodCallParams, error) {
	algodClient := GetAlgodClient()
	account, err := GetDefaultAccount()
	if err != nil {
		return nil, fmt.Errorf("failed to get localnet default account: %v",
			err)
	}
	sp, err := algodClient.SuggestedParams().Do(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get suggested params: %v", err)
	}
	method, err := schema.Contract.GetMethodByName(methodName)
	if err != nil {
		return nil, fmt.Errorf("failed to get method %s: %v", methodName, err)
	}

	var sender types.Address
	if signer == nil {
		sender = account.Address
		signer = transaction.BasicAccountTransactionSigner{Account: *account}
	} else {
		switch signer := signer.(type) {
		case transaction.BasicAccountTransactionSigner:
			sender = signer.Account.Address
		case transaction.LogicSigAccountTransactionSigner:
			sender, err = signer.LogicSigAccount.Address()
			if err != nil {
				return nil, fmt.Errorf("failed to get lsig address: %v", err)
			}
		default:
			return nil, fmt.Errorf("unsupported signer type: %T", signer)
		}
	}
	return &transaction.AddMethodCallParams{
		AppID:           appId,
		Sender:          sender,
		SuggestedParams: sp,
		OnComplete:      oc,
		Signer:          signer,
		Method:          method,
		MethodArgs:      methodArgs,
		BoxReferences:   boxes,
	}, nil
}

// ExecuteAbiCall calls an abi method on an app and returns the result.
// If signer is nil, it uses the default localnet account for both.
// A local network must be running
func ExecuteAbiCall(
	appId uint64, schema *Arc32Schema, methodName string,
	oc types.OnCompletion, methodArgs []interface{},
	boxes []types.AppBoxReference, signer transaction.TransactionSigner,
	simulate bool,
) (*transaction.ABIMethodResult, error) {

	algodClient := GetAlgodClient()

	var atc = transaction.AtomicTransactionComposer{}
	txnParams, err := BuildMethodCallParams(appId, schema, methodName, oc, methodArgs,
		boxes, signer)
	if err != nil {
		return nil, fmt.Errorf("failed to build method call params: %v", err)
	}
	if err := atc.AddMethodCall(*txnParams); err != nil {
		return nil, fmt.Errorf("failed to add method call: %v", err)
	}
	if simulate {
		simReq := models.SimulateRequest{ExtraOpcodeBudget: 320000}
		simRes, err_ := atc.Simulate(context.Background(), algodClient, simReq)
		if err_ != nil {
			return nil, fmt.Errorf("failed to simulate verify txn: %v", err)
		}
		if simRes.SimulateResponse.TxnGroups[0].FailureMessage != "" {
			return nil, fmt.Errorf("transaction failed: %s",
				simRes.SimulateResponse.TxnGroups[0].FailureMessage)
		}
		budgetConsumed := simRes.SimulateResponse.TxnGroups[0].AppBudgetConsumed
		fmt.Println("Budget consumed: ", budgetConsumed)
		abiResult := simRes.MethodResults[len(simRes.MethodResults)-1]
		return &abiResult, nil
	}
	res, err := atc.Execute(algodClient, context.Background(), 4)
	if err != nil {
		return nil, fmt.Errorf("failed to execute txn: %v", err)
	}
	return &res.MethodResults[len(res.MethodResults)-1], nil
}

// GetDefaultAccount returns the default account for the local network
// A local network must be running
func GetDefaultAccount() (account *crypto.Account, err error) {
	accts, err := GetSandboxAccounts()
	if err != nil {
		return nil, fmt.Errorf("failed to get localnet accounts: %s.\n"+
			"Make sure you are running a local Algorand network with default "+
			"parameters or have setup correct custom parameters", err)
	}
	return &accts[0], nil
}

// EnsureFunded checks if the given address has at least min microalgos
// and if not funds it with twice the amount from the default account.
// A local network must be running
func EnsureFunded(address string, min uint64) {
	algodClient := GetAlgodClient()
	account, err := algodClient.AccountInformation(address).Do(
		context.Background())
	if err != nil {
		log.Fatalf("failed to get account information: %v", err)
	}
	if account.Amount < uint64(min) {
		account, err := GetDefaultAccount()
		if err != nil {
			log.Fatalf("failed to get localnet default account: %v", err)
		}
		sp, err := algodClient.SuggestedParams().Do(context.Background())
		if err != nil {
			log.Fatalf("failed to get suggested params: %v", err)
		}
		txn, err := transaction.MakePaymentTxn(account.Address.String(),
			address, 2*min, nil, types.ZeroAddress.String(), sp)
		if err != nil {
			log.Fatalf("failed to make payment txn: %v", err)
		}
		_, err = SendTxn(txn, account)
		if err != nil {
			log.Fatalf("error sending payment transaction:  %v", err)
		}
	}
}

// DeployApp deploys a smart contract application and returns its id
// A local network must be running with default parameters
func DeployApp(approvalTeal []byte, clearTeal []byte) (uint64, error) {
	algodClient := GetAlgodClient()

	creator, err := GetDefaultAccount()
	if err != nil {
		return 0, fmt.Errorf("failed to get localnet default account: %v", err)
	}

	var (
		approvalBinary = make([]byte, 1000)
		clearBinary    = make([]byte, 1000)
	)

	approvalResult, err := algodClient.TealCompile(approvalTeal).
		Do(context.Background())
	if err != nil {
		return 0, fmt.Errorf("failed to compile program: %s", err)
	}
	_, err = base64.StdEncoding.Decode(approvalBinary, []byte(approvalResult.Result))
	if err != nil {
		return 0, fmt.Errorf("failed to decode compiled program: %s", err)
	}

	clearResult, err := algodClient.TealCompile(clearTeal).
		Do(context.Background())
	if err != nil {
		return 0, fmt.Errorf("failed to compile program: %s", err)
	}
	_, err = base64.StdEncoding.Decode(clearBinary, []byte(clearResult.Result))
	if err != nil {
		return 0, fmt.Errorf("failed to decode compiled program: %s", err)
	}

	// Create application
	sp, err := algodClient.SuggestedParams().Do(context.Background())
	if err != nil {
		return 0, fmt.Errorf("error getting suggested tx params: %s", err)
	}

	txn, err := transaction.MakeApplicationCreateTx(
		false, approvalBinary, clearBinary,
		types.StateSchema{}, types.StateSchema{},
		nil, nil, nil, nil,
		sp, creator.Address, nil,
		types.Digest{}, [32]byte{}, types.ZeroAddress,
	)
	if err != nil {
		return 0, fmt.Errorf("failed to make txn: %s", err)
	}

	confirmedTxn, err := SendTxn(txn, creator)
	if err != nil {
		return 0, fmt.Errorf("error sending create transaction:  %v", err)
	}
	return confirmedTxn.ApplicationIndex, nil
}

// DeleteApp deletes an application by its id
// A local network must be running with default parameters
func DeleteApp(appId uint64) error {
	algodClient := GetAlgodClient()
	sender, err := GetDefaultAccount()
	if err != nil {
		return fmt.Errorf("failed to get localnet default account: %v", err)
	}

	sp, err := algodClient.SuggestedParams().Do(context.Background())
	if err != nil {
		return fmt.Errorf("failed to get suggested tx params: %v", err)
	}
	txn, err := transaction.MakeApplicationDeleteTx(
		appId, nil, nil, nil, nil, sp, sender.Address, nil, types.Digest{}, [32]byte{}, types.ZeroAddress,
	)
	if err != nil {
		return fmt.Errorf("failed to make delete txn: %v", err)
	}

	_, err = SendTxn(txn, sender)
	if err != nil {
		return fmt.Errorf("error sending delete app transaction:  %v", err)
	}
	return nil
}

// LogicSigFromFile returns a logicsig account from a teal file
// A local network must be running with default parameters
func LogicSigFromFile(filename string) (*crypto.LogicSigAccount, error) {
	teal, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read program from file: %v", err)
	}
	algod := GetAlgodClient()
	result, err := algod.TealCompile(teal).Do(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to compile program: %v", err)
	}
	lsigBinary, err := base64.StdEncoding.DecodeString(result.Result)
	if err != nil {
		return nil, fmt.Errorf("failed to decode compiled program: %v", err)
	}
	return &crypto.LogicSigAccount{
		Lsig: types.LogicSig{Logic: lsigBinary, Args: nil},
	}, nil
}

// AddDummyTrasactions adds numberOfTxnToAdd dummy transactions to atc.
// The last transaction will have a fee of 1 algo to cover the fee for the group.
// A local network must be running with default parameters
func AddDummyTrasactions(atc *transaction.AtomicTransactionComposer,
	numberOfTxnToAdd int) error {
	algod := GetAlgodClient()
	account, err := GetDefaultAccount()
	if err != nil {
		return fmt.Errorf("failed to get localnet default account: %v", err)
	}
	sp, err := algod.SuggestedParams().Do(context.Background())
	sp.FlatFee = true
	sp.Fee = 0
	if err != nil {
		return fmt.Errorf("failed to get suggested params: %v", err)
	}
	for i := 0; i < numberOfTxnToAdd; i++ {
		txn, err := transaction.MakePaymentTxn(account.Address.String(),
			account.Address.String(), 0, []byte{byte(i)}, types.ZeroAddress.String(), sp)
		if err != nil {
			return fmt.Errorf("failed to make payment txn: %v", err)
		}
		if i == numberOfTxnToAdd-1 {
			txn.Fee = 1_000_000
		}
		txnWithSigner := transaction.TransactionWithSigner{
			Txn:    txn,
			Signer: transaction.BasicAccountTransactionSigner{Account: *account},
		}
		if err := atc.AddTransaction(txnWithSigner); err != nil {
			return fmt.Errorf("failed to add transaction: %v", err)
		}
	}
	return nil
}

// ExecuteGroup executes a transaction group composed by atc.
// If simulate is true, it simulates the group instead of sending it.
// A local network must be running with default parameters
func ExecuteGroup(atc *transaction.AtomicTransactionComposer, simulate bool,
) (*transaction.ExecuteResult, error) {
	algod := GetAlgodClient()
	if simulate {
		simReq := models.SimulateRequest{ExtraOpcodeBudget: 320000}
		simRes, err := atc.Simulate(context.Background(), algod, simReq)
		if err != nil {
			return nil, fmt.Errorf("failed to simulate verify txn: %v", err)
		}
		trxError := simRes.SimulateResponse.TxnGroups[0].FailureMessage
		if trxError != "" {
			return nil, fmt.Errorf("transaction failed: %s", trxError)
		}
		appBudgetConsumed := simRes.SimulateResponse.TxnGroups[0].AppBudgetConsumed
		fmt.Println("App opcode budget consumed: ", appBudgetConsumed)

		lsigBudgetConsumed := simRes.SimulateResponse.TxnGroups[0].TxnResults[0].LogicSigBudgetConsumed
		fmt.Println("LogicSig budget consumed: ", lsigBudgetConsumed)

		return nil, nil
	}
	res, err := atc.Execute(algod, context.Background(), 4)
	if err != nil {
		return nil, fmt.Errorf("failed to execute txn: %v", err)
	}
	return &res, nil
}
