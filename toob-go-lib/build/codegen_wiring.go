package build

import (
	"cmp"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
)

type wiringAdapter struct {
	returnType string
	name       string
	guard      string
	bodyLines  []string
}

type wiringFieldInit struct {
	field string
	expr  string
	guard string
}

type resolvedTrait struct {
	contract     halTraitContract
	instantiated bool
	platformExpr string
	adapters     []wiringAdapter
	fields       []wiringFieldInit
	boundMethods map[string]string
}

type boundCryptoPkg struct {
	manifest  *CryptoManifest
	unguarded bool
	guards    []string
}

func (b *boundCryptoPkg) recordGuard(guard string) {
	if guard == "" {
		b.unguarded = true
		return
	}
	pureConjGuard := !strings.Contains(guard, "||") && !strings.Contains(guard, "?")
	for i, existing := range b.guards {
		if existing == guard {
			return
		}
		pureConjExisting := !strings.Contains(existing, "||") && !strings.Contains(existing, "?")
		if pureConjGuard && pureConjExisting {
			if strings.HasSuffix(guard, " && "+existing) || strings.HasPrefix(guard, existing+" && ") {
				return
			}
			if strings.HasSuffix(existing, " && "+guard) || strings.HasPrefix(existing, guard+" && ") {
				b.guards[i] = guard
				return
			}
		}
	}
	b.guards = append(b.guards, guard)
}

// renderPlatformWiringWithConsumed renders generated_platform_wiring.c purely
// from hal_contract.json and the bound arch, driver, and crypto manifests.
// When distinct Recovery OS drivers or crypto packages are supplied on Context,
// it emits #ifndef TOOB_RECOVERY_BUILD ... #else ... #endif (HIGH-56).
func renderPlatformWiringWithConsumed(ctx *Context) ([]byte, []string, []string, error) {
	if ctx == nil {
		return nil, nil, nil, errors.New("FATAL: platform wiring context must not be nil")
	}
	if len(ctx.RecoveryDrivers) == 0 && len(ctx.RecoveryCrypto) == 0 {
		return renderSingleStageWiring(ctx, false)
	}

	stageCtx := *ctx
	stageCtx.RecoveryDrivers = nil
	stageCtx.RecoveryCrypto = nil
	stageData, stageReq, stageCons, err := renderSingleStageWiring(&stageCtx, false)
	if err != nil {
		return nil, nil, nil, err
	}

	recCtx := *ctx
	mergedDrivers := maps.Clone(ctx.Drivers)
	if mergedDrivers == nil {
		mergedDrivers = make(map[string]*DriverManifest, len(ctx.RecoveryDrivers))
	}
	maps.Copy(mergedDrivers, ctx.RecoveryDrivers)
	recCtx.Drivers = mergedDrivers
	if len(ctx.RecoveryCrypto) > 0 {
		recCtx.Crypto = ctx.RecoveryCrypto
	}
	recCtx.RecoveryDrivers = nil
	recCtx.RecoveryCrypto = nil
	recData, recReq, recCons, err := renderSingleStageWiring(&recCtx, true)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("recovery wiring: %w", err)
	}

	stripBanner := func(raw []byte) string {
		txt := string(raw)
		return strings.TrimPrefix(txt, generatedBanner+"\n")
	}
	s := newCFile()
	s.line("#ifndef TOOB_RECOVERY_BUILD")
	s.b.WriteString(stripBanner(stageData))
	s.line("#else /* TOOB_RECOVERY_BUILD */")
	s.b.WriteString(stripBanner(recData))
	s.line("#endif /* TOOB_RECOVERY_BUILD */")
	combined, err := s.finish()
	if err != nil {
		return nil, nil, nil, err
	}

	req := slices.Clone(stageReq)
	for _, m := range recReq {
		if !slices.Contains(req, m) {
			req = append(req, m)
		}
	}
	cons := slices.Clone(stageCons)
	for _, m := range recCons {
		if !slices.Contains(cons, m) {
			cons = append(cons, m)
		}
	}
	return combined, req, cons, nil
}

func renderSingleStageWiring(ctx *Context, isRecovery bool) ([]byte, []string, []string, error) {
	if ctx == nil {
		return nil, nil, nil, errors.New("FATAL: platform wiring context must not be nil")
	}
	hc := ctx.halContract
	if hc == nil {
		return nil, nil, nil, errors.New("FATAL: platform wiring requires a loaded hal_contract.json")
	}
	if err := validateHalContract(hc); err != nil {
		return nil, nil, nil, fmt.Errorf("FATAL: platform wiring invalid HAL contract: %w", err)
	}
	if ctx.Chip == nil {
		return nil, nil, nil, errors.New("FATAL: platform wiring requires a chip manifest")
	}

	archHeaders, archMacros, err := validateWiringArch(ctx, hc)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("FATAL: platform wiring: %w", err)
	}

	if vErr := validateAllDriversForWiring(ctx.Drivers, hc); vErr != nil {
		return nil, nil, nil, vErr
	}

	cryptoByCat, err := indexCryptoByCategory(ctx.Crypto)
	if err != nil {
		return nil, nil, nil, err
	}
	if !isRecovery {
		if pqcRef, pqcEnabled := effectiveCryptoPqc(ctx); pqcEnabled && cryptoByCat["pqc"] == nil {
			return nil, nil, nil, fmt.Errorf("FATAL: crypto.pqc = %q is enabled, but no PQC crypto manifest is bound", pqcRef)
		}
	}

	var (
		requiredMacros []string
		consumedMacros []string
		boundDrivers   []*DriverManifest
		seenDriverPtrs = make(map[*DriverManifest]bool)
		boundCryptoMap = make(map[*CryptoManifest]*boundCryptoPkg)
		missing        []string
	)
	addRequiredMacro := func(m string) {
		if m != "" && !slices.Contains(requiredMacros, m) {
			requiredMacros = append(requiredMacros, m)
		}
	}
	addConsumedMacro := func(m string) {
		addRequiredMacro(m)
		if m != "" && !slices.Contains(consumedMacros, m) {
			consumedMacros = append(consumedMacros, m)
		}
	}
	for _, m := range archMacros {
		addRequiredMacro(m)
	}

	markDriverBound := func(dm *DriverManifest, fallbackTrait string) error {
		if dm == nil || seenDriverPtrs[dm] {
			return nil
		}
		label := cmp.Or(dm.Name, dm.Trait, fallbackTrait)
		if len(dm.Headers) == 0 {
			return fmt.Errorf("FATAL: driver '%s' manifest must declare at least one header in 'headers'", label)
		}
		for _, h := range dm.Headers {
			if hErr := validateHeaderPath(h); hErr != nil {
				return fmt.Errorf("FATAL: driver '%s' declares an invalid header path %q: %w", label, h, hErr)
			}
		}
		seenDriverPtrs[dm] = true
		boundDrivers = append(boundDrivers, dm)
		return nil
	}

	markCryptoBound := func(cm *CryptoManifest, trait halTraitContract, guard string) error {
		if cm.AbiVersion != "" && trait.AbiVersion != "" && !strings.EqualFold(cm.AbiVersion, trait.AbiVersion) {
			return fmt.Errorf("FATAL: crypto '%s' declares abi_version %q, but HAL contract trait '%s' requires %q",
				cm.Name, cm.AbiVersion, trait.Name, trait.AbiVersion)
		}
		if len(cm.Headers) == 0 {
			return fmt.Errorf("FATAL: crypto '%s' manifest must declare at least one header in 'headers'", cm.Name)
		}
		for _, h := range cm.Headers {
			if hErr := validateHeaderPath(h); hErr != nil {
				return fmt.Errorf("FATAL: crypto '%s' declares an invalid header path %q: %w", cm.Name, h, hErr)
			}
		}
		entry := boundCryptoMap[cm]
		if entry == nil {
			entry = &boundCryptoPkg{manifest: cm}
			boundCryptoMap[cm] = entry
		}
		entry.recordGuard(guard)
		return nil
	}

	resolved := make([]resolvedTrait, 0, len(hc.Traits))
	resolvedByName := make(map[string]resolvedTrait, len(hc.Traits))

	for idx := range hc.Traits {
		trait := &hc.Traits[idx]
		rt := resolvedTrait{
			contract:     *trait,
			platformExpr: "NULL",
			boundMethods: make(map[string]string),
		}

		var primaryDriver *DriverManifest
		if trait.InstantiateWhen == "driver_bound" {
			dm, dErr := selectSingleTraitDriver(ctx.Drivers, *trait)
			if dErr != nil {
				return nil, nil, nil, dErr
			}
			if dm == nil {
				if !trait.Optional {
					missing = append(missing, "driver:"+trait.Name)
				}
				resolved = append(resolved, rt)
				resolvedByName[trait.Name] = rt
				continue
			}
			if bErr := markDriverBound(dm, trait.Name); bErr != nil {
				return nil, nil, nil, bErr
			}
			primaryDriver = dm
		}

		if trait.BindingMode == "symbol_pointer" {
			if primaryDriver == nil {
				if !trait.Optional {
					missing = append(missing, trait.Name+"."+trait.SymbolKey)
				}
				resolved = append(resolved, rt)
				resolvedByName[trait.Name] = rt
				continue
			}
			sym := primaryDriver.Symbols[trait.SymbolKey]
			if !isCSymbol(sym) {
				return nil, nil, nil, fmt.Errorf("FATAL: %s driver '%s' must declare a valid '%s' symbol, got %q",
					trait.Name, cmp.Or(primaryDriver.Name, trait.Name), trait.SymbolKey, sym)
			}
			rt.instantiated = true
			rt.platformExpr = "&" + sym
			resolved = append(resolved, rt)
			resolvedByName[trait.Name] = rt
			continue
		}

		if trait.AbiConstant != "" {
			rt.fields = append(rt.fields, wiringFieldInit{field: "abi_version", expr: trait.AbiConstant})
		}

		var boundMethodCount int
		var methodDrivers []*DriverManifest

		for mIdx := range trait.Methods {
			m := &trait.Methods[mIdx]
			expr, usedDriver, mErr := resolveTraitMethod(ctx, *trait, *m, primaryDriver, cryptoByCat, &rt.adapters, addRequiredMacro, markCryptoBound, &missing)
			if mErr != nil {
				return nil, nil, nil, mErr
			}
			if expr == "" {
				continue
			}
			if usedDriver != nil && !slices.Contains(methodDrivers, usedDriver) {
				methodDrivers = append(methodDrivers, usedDriver)
			}
			rt.fields = append(rt.fields, wiringFieldInit{
				field: m.Field,
				expr:  expr,
				guard: m.Guard,
			})
			rt.boundMethods[m.Field] = expr
			boundMethodCount++
		}

		switch trait.InstantiateWhen {
		case "always", "driver_bound":
			rt.instantiated = true
		case "any_method_bound":
			rt.instantiated = boundMethodCount > 0
			if !rt.instantiated && !trait.Optional {
				missing = append(missing, "trait:"+trait.Name)
			}
		}

		if rt.instantiated && trait.RequireAnyMethod && boundMethodCount == 0 {
			label := trait.Name
			if primaryDriver != nil && primaryDriver.Name != "" {
				label = primaryDriver.Name
			}
			return nil, nil, nil, fmt.Errorf("FATAL: %s driver '%s' must bind at least one method for trait '%s'",
				trait.Name, label, trait.Name)
		}

		if rt.instantiated {
			for _, dm := range methodDrivers {
				if bErr := markDriverBound(dm, trait.Name); bErr != nil {
					return nil, nil, nil, bErr
				}
			}
			for _, prop := range trait.Properties {
				val, pErr := resolveTraitProperty(ctx, *trait, prop, primaryDriver, boundCryptoMap, addRequiredMacro, addConsumedMacro)
				if pErr != nil {
					return nil, nil, nil, pErr
				}
				rt.fields = append(rt.fields, wiringFieldInit{
					field: prop.Field,
					expr:  val,
				})
			}
			rt.platformExpr = "&g_platform_" + trait.Name + "_hal"
		}

		resolved = append(resolved, rt)
		resolvedByName[trait.Name] = rt
	}

	if len(missing) > 0 {
		return nil, nil, nil, fmt.Errorf("FATAL: manifests do not provide a complete HAL binding; missing: %s",
			strings.Join(missing, ", "))
	}

	boundCryptos := make([]*boundCryptoPkg, 0, len(boundCryptoMap))
	for _, cm := range ctx.Crypto {
		if b := boundCryptoMap[cm]; b != nil {
			boundCryptos = append(boundCryptos, b)
		}
	}

	s := newCFile()
	renderWiringIncludes(s, hc.CoreHeaders, archHeaders, boundDrivers, boundCryptos)
	renderTraitStructs(s, resolved)
	if rErr := renderPlatformAndBringup(s, ctx, hc, resolved, resolvedByName); rErr != nil {
		return nil, nil, nil, rErr
	}

	data, err := s.finish()
	if err != nil {
		return nil, nil, nil, err
	}
	return data, requiredMacros, consumedMacros, nil
}

func validateWiringArch(ctx *Context, hc *halContract) ([]string, []string, error) {
	if strings.TrimSpace(ctx.Chip.Arch) == "" {
		return nil, nil, errors.New("chip_manifest.json 'arch' must not be empty")
	}
	if err := ValidatePackageRef("arch", ctx.Chip.Arch); err != nil {
		return nil, nil, err
	}
	am := ctx.Arch
	if am == nil {
		return nil, nil, fmt.Errorf("missing arch_manifest.json for registered architecture '%s'", ctx.Chip.Arch)
	}
	if am.Name != "" && !strings.EqualFold(am.Name, ctx.Chip.Arch) {
		return nil, nil, fmt.Errorf("arch_manifest.json name '%s' does not match chip_manifest.json arch '%s'", am.Name, ctx.Chip.Arch)
	}
	if len(am.Headers) == 0 {
		return nil, nil, fmt.Errorf("arch '%s' manifest must declare at least one header in 'headers'", ctx.Chip.Arch)
	}
	headers := make([]string, 0, len(am.Headers))
	for _, h := range am.Headers {
		if err := validateHeaderPath(h); err != nil {
			return nil, nil, fmt.Errorf("arch '%s' declares an invalid header path %q: %w", ctx.Chip.Arch, h, err)
		}
		if !slices.Contains(headers, h) {
			headers = append(headers, h)
		}
	}

	reqSyms := slices.Clone(hc.Arch.RequiredSymbols)
	if hc.Arch.EntryIRQDisableSymbol != "" && !slices.Contains(reqSyms, hc.Arch.EntryIRQDisableSymbol) {
		reqSyms = append(reqSyms, hc.Arch.EntryIRQDisableSymbol)
	}

	var missing, invalid []string
	for _, key := range reqSyms {
		sym := am.Symbols[key]
		switch {
		case sym == "":
			missing = append(missing, "arch."+key)
		case !isCSymbol(sym):
			invalid = append(invalid, fmt.Sprintf("arch.%s=%q", key, sym))
		}
	}
	for _, key := range slices.Sorted(maps.Keys(am.Symbols)) {
		if slices.Contains(reqSyms, key) {
			continue
		}
		if err := ValidateName("arch symbol key", key); err != nil || !isCSymbol(am.Symbols[key]) {
			invalid = append(invalid, fmt.Sprintf("arch.%s=%q", key, am.Symbols[key]))
		}
	}
	if len(missing) > 0 || len(invalid) > 0 {
		var msg strings.Builder
		fmt.Fprintf(&msg, "arch '%s' manifest does not provide a valid HAL binding", ctx.Chip.Arch)
		if len(missing) > 0 {
			msg.WriteString("; missing symbols: " + strings.Join(missing, ", "))
		}
		if len(invalid) > 0 {
			msg.WriteString("; invalid C identifiers: " + strings.Join(invalid, ", "))
		}
		return nil, nil, errors.New(msg.String())
	}

	reqMacros := slices.Clone(hc.Arch.BaseRequiredMacros)
	for _, m := range am.RequiredMacros {
		if !isCIdentifier(m) {
			return nil, nil, fmt.Errorf("arch '%s' declares invalid required macro %q", ctx.Chip.Arch, m)
		}
		if !slices.Contains(reqMacros, m) {
			reqMacros = append(reqMacros, m)
		}
	}
	return headers, reqMacros, nil
}

func findDriverOwnerTrait(hc *halContract, driverTrait string) *halTraitContract {
	for i := range hc.Traits {
		if hc.Traits[i].Name == driverTrait {
			return &hc.Traits[i]
		}
	}
	for i := range hc.Traits {
		t := &hc.Traits[i]
		if t.InstantiateWhen == "driver_bound" && slices.Contains(t.DriverTraits, driverTrait) {
			return t
		}
	}
	return nil
}

func validateAllDriversForWiring(drivers map[string]*DriverManifest, hc *halContract) error {
	var invalid []string
	for _, key := range slices.Sorted(maps.Keys(drivers)) {
		dm := drivers[key]
		if dm == nil {
			continue
		}
		traitName := cmp.Or(dm.Trait, key)
		if err := ValidateName("driver trait", traitName); err != nil {
			return fmt.Errorf("FATAL: driver '%s': %w", cmp.Or(dm.Name, key), err)
		}
		if dm.Name != "" {
			if err := ValidatePackageRef("driver", dm.Name); err != nil {
				return fmt.Errorf("FATAL: driver '%s': %w", dm.Name, err)
			}
		}
		owner := findDriverOwnerTrait(hc, traitName)
		if owner != nil && dm.AbiVersion != "" && owner.AbiVersion != "" && !strings.EqualFold(dm.AbiVersion, owner.AbiVersion) {
			return fmt.Errorf("FATAL: driver '%s' (trait '%s') declares abi_version %q, but HAL contract trait '%s' requires %q",
				cmp.Or(dm.Name, traitName), traitName, dm.AbiVersion, owner.Name, owner.AbiVersion)
		}
		for _, symKey := range slices.Sorted(maps.Keys(dm.Symbols)) {
			symVal := dm.Symbols[symKey]
			if symVal == "" {
				continue
			}
			if err := ValidateName("driver symbol key", symKey); err != nil || !isCSymbol(symVal) {
				invalid = append(invalid, fmt.Sprintf("%s.%s=%q", traitName, symKey, symVal))
			}
		}
	}
	if len(invalid) > 0 {
		return fmt.Errorf("FATAL: driver manifests declare invalid C identifiers: %s", strings.Join(invalid, ", "))
	}
	return nil
}

func indexCryptoByCategory(cryptos []*CryptoManifest) (map[string]*CryptoManifest, error) {
	byCat := make(map[string]*CryptoManifest)
	for _, cm := range cryptos {
		if err := validateCryptoManifest(cm); err != nil {
			return nil, fmt.Errorf("FATAL: crypto manifest: %w", err)
		}
		for _, cat := range cm.Category {
			if prev := byCat[cat]; prev != nil {
				return nil, fmt.Errorf("FATAL: crypto category '%s' is bound twice ('%s' and '%s')", cat, prev.Name, cm.Name)
			}
			byCat[cat] = cm
		}
	}
	return byCat, nil
}

func selectSingleTraitDriver(drivers map[string]*DriverManifest, trait halTraitContract) (*DriverManifest, error) {
	candidates := trait.DriverTraits
	if len(candidates) == 0 {
		candidates = []string{trait.Name}
	}
	var matched []*DriverManifest
	var matchedKeys []string
	for _, dt := range candidates {
		if dm := drivers[dt]; dm != nil && !slices.Contains(matched, dm) {
			matched = append(matched, dm)
			matchedKeys = append(matchedKeys, dt)
		}
	}
	if len(matched) > 1 {
		return nil, fmt.Errorf("FATAL: trait '%s' cannot bind multiple drivers simultaneously (%s)",
			trait.Name, strings.Join(matchedKeys, ", "))
	}
	if len(matched) == 1 {
		return matched[0], nil
	}
	return nil, nil
}

func findMethodDriverSymbol(drivers map[string]*DriverManifest, trait halTraitContract, m halMethodContract, primary *DriverManifest) (string, *DriverManifest) {
	if primary != nil && len(m.DriverTraits) == 0 {
		return primary.Symbols[m.Key], primary
	}
	candidates := m.DriverTraits
	if len(candidates) == 0 {
		candidates = trait.DriverTraits
	}
	if len(candidates) == 0 {
		candidates = []string{trait.Name}
	}
	for _, dt := range candidates {
		if dm := drivers[dt]; dm != nil {
			if sym := dm.Symbols[m.Key]; sym != "" {
				return sym, dm
			}
		}
	}
	return "", nil
}

func resolveTraitMethod(
	ctx *Context,
	trait halTraitContract,
	m halMethodContract,
	primaryDriver *DriverManifest,
	cryptoByCat map[string]*CryptoManifest,
	adapters *[]wiringAdapter,
	addRequiredMacro func(string),
	markCryptoBound func(*CryptoManifest, halTraitContract, string) error,
	missing *[]string,
) (string, *DriverManifest, error) {
	switch m.Source {
	case "driver":
		sym, dm := findMethodDriverSymbol(ctx.Drivers, trait, m, primaryDriver)
		if sym == "" {
			if m.Required {
				*missing = append(*missing, trait.Name+"."+m.Key)
			}
			return "", nil, nil
		}
		return sym, dm, nil

	case "arch":
		sym := ctx.Arch.Symbols[m.Key]
		if sym == "" {
			if m.Required {
				*missing = append(*missing, "arch."+m.Key)
			}
			return "", nil, nil
		}
		if !isCSymbol(sym) {
			return "", nil, fmt.Errorf("FATAL: arch '%s' invalid C identifier arch.%s=%q", ctx.Chip.Arch, m.Key, sym)
		}
		return sym, nil, nil

	case "arch_timer_init_adapter":
		if m.DriverOverrideKey != "" && primaryDriver != nil {
			if override := primaryDriver.Symbols[m.DriverOverrideKey]; override != "" {
				return override, primaryDriver, nil
			}
		}
		archSym := ctx.Arch.Symbols[m.Key]
		if archSym == "" {
			if m.Required {
				*missing = append(*missing, "arch."+m.Key)
			}
			return "", nil, nil
		}
		if !isCSymbol(archSym) {
			return "", nil, fmt.Errorf("FATAL: arch '%s' invalid C identifier arch.%s=%q", ctx.Chip.Arch, m.Key, archSym)
		}
		addRequiredMacro(m.ArgMacro)
		wrapper := "g_" + trait.Name + "_" + m.Field + "_wrapper"
		*adapters = append(*adapters, wiringAdapter{
			returnType: "boot_status_t",
			name:       wrapper,
			guard:      m.Guard,
			bodyLines: []string{
				fmt.Sprintf("%s(%s);", archSym, m.ArgMacro),
				"return BOOT_OK;",
			},
		})
		return wrapper, nil, nil

	case "noop_void_adapter":
		if m.DriverOverrideKey != "" && primaryDriver != nil {
			if override := primaryDriver.Symbols[m.DriverOverrideKey]; override != "" {
				return override, primaryDriver, nil
			}
		}
		wrapper := "g_" + trait.Name + "_" + m.Field + "_wrapper"
		*adapters = append(*adapters, wiringAdapter{
			returnType: "void",
			name:       wrapper,
			guard:      m.Guard,
		})
		return wrapper, nil, nil

	case "crypto":
		cm := cryptoByCat[m.CryptoCategory]
		if cm == nil {
			// PQC is optional at the device configuration level unless a PQC manifest is bound.
			if m.CryptoCategory == "pqc" || !m.Required {
				return "", nil, nil
			}
			*missing = append(*missing, fmt.Sprintf("crypto[%s].%s", m.CryptoCategory, m.Key))
			return "", nil, nil
		}
		sym := cm.Symbols[m.Key]
		if sym == "" {
			if m.Required {
				*missing = append(*missing, fmt.Sprintf("crypto(%s).%s", cm.Name, m.Key))
			}
			return "", nil, nil
		}
		if err := markCryptoBound(cm, trait, m.Guard); err != nil {
			return "", nil, err
		}
		return sym, nil, nil

	default:
		return "", nil, fmt.Errorf("FATAL: unsupported method source %q on %s.%s", m.Source, trait.Name, m.Field)
	}
}

func findHardwareConstMacro(hw *HardwareJson, target string) string {
	if hw == nil || target == "" {
		return ""
	}
	for k := range hw.Constants {
		if strings.EqualFold(k, target) {
			return "CHIP_" + strings.ToUpper(k)
		}
	}
	return ""
}

func resolveTraitProperty(
	ctx *Context,
	trait halTraitContract,
	prop halPropertyContract,
	boundDriver *DriverManifest,
	boundCryptoMap map[*CryptoManifest]*boundCryptoPkg,
	addRequiredMacro func(string),
	addConsumedMacro func(string),
) (string, error) {
	switch prop.Source {
	case "macro":
		if !isCIdentifier(prop.Expr) {
			return "", fmt.Errorf("FATAL: invalid macro identifier %q on %s.%s", prop.Expr, trait.Name, prop.Field)
		}
		addRequiredMacro(prop.Expr)
		return prop.Expr, nil

	case "flash_max_erase_cycles":
		if ctx.Chip != nil && ctx.Chip.SlotCapabilities != nil && ctx.Chip.SlotCapabilities.MaxEraseCycles > 0 {
			return fmt.Sprintf("%dU", ctx.Chip.SlotCapabilities.MaxEraseCycles), nil
		}
		if m := findHardwareConstMacro(ctx.Hardware, "flash_max_erase_cycles"); m != "" {
			addConsumedMacro(m)
			return m, nil
		}
		return prop.Default, nil

	case "flash_timing_us":
		if ctx.Hardware != nil {
			switch prop.HwKey {
			case "erase_time_us_max":
				if ctx.Hardware.Flash.EraseTimeUsMax != 0 {
					return fmt.Sprintf("%dU", ctx.Hardware.Flash.EraseTimeUsMax), nil
				}
			case "write_time_us_page":
				if ctx.Hardware.Flash.WriteTimeUsPage != 0 {
					return fmt.Sprintf("%dU", ctx.Hardware.Flash.WriteTimeUsPage), nil
				}
			}
			for _, candidate := range []string{
				strings.TrimPrefix(prop.ChipMacro, "CHIP_"),
				"flash_" + prop.HwKey,
				prop.HwKey,
			} {
				if m := findHardwareConstMacro(ctx.Hardware, candidate); m != "" {
					addConsumedMacro(m)
					return m, nil
				}
			}
		}
		return prop.Default, nil

	case "hardware_uint":
		if ctx.Hardware != nil {
			for _, candidate := range []string{
				strings.TrimPrefix(prop.ChipMacro, "CHIP_"),
				prop.HwKey,
			} {
				if m := findHardwareConstMacro(ctx.Hardware, candidate); m != "" {
					addConsumedMacro(m)
					return m, nil
				}
			}
		}
		return prop.Default, nil

	case "driver_bool":
		def := cmp.Or(prop.Default, "false")
		if prop.Key == "is_hardware_trng" && boundDriver != nil {
			if boundDriver.IsHardwareTRNG {
				return "true", nil
			}
			return "false", nil
		}
		return def, nil

	case "crypto_bool":
		def := cmp.Or(prop.Default, "false")
		if prop.Key == "has_hw_acceleration" {
			for cm := range boundCryptoMap {
				if cm.HasHwAcceleration {
					return "true", nil
				}
			}
			return def, nil
		}
		return def, nil

	default:
		return "", fmt.Errorf("FATAL: unsupported property source %q on %s.%s", prop.Source, trait.Name, prop.Field)
	}
}

func renderWiringIncludes(
	s *cSource,
	coreHeaders []string,
	archHeaders []string,
	boundDrivers []*DriverManifest,
	boundCryptos []*boundCryptoPkg,
) {
	emitted := make(map[string]bool)
	emitInclude := func(h string) {
		if emitted[h] {
			return
		}
		emitted[h] = true
		s.line(`#include "` + h + `"`)
	}

	for _, h := range coreHeaders {
		emitInclude(h)
	}
	s.blank()

	for _, h := range archHeaders {
		emitInclude(h)
	}

	sortedDrivers := slices.Clone(boundDrivers)
	slices.SortStableFunc(sortedDrivers, func(a, b *DriverManifest) int {
		if c := cmp.Compare(a.Trait, b.Trait); c != 0 {
			return c
		}
		return cmp.Compare(a.Name, b.Name)
	})
	for _, dm := range sortedDrivers {
		for _, h := range dm.Headers {
			emitInclude(h)
		}
	}

	for _, bc := range boundCryptos {
		var pending []string
		for _, h := range bc.manifest.Headers {
			if !emitted[h] {
				pending = append(pending, h)
			}
		}
		if len(pending) == 0 {
			continue
		}
		if bc.unguarded || len(bc.guards) == 0 {
			for _, h := range pending {
				emitInclude(h)
			}
			continue
		}
		guardExpr := bc.guards[0]
		if len(bc.guards) > 1 {
			wrapped := make([]string, len(bc.guards))
			for i, g := range bc.guards {
				wrapped[i] = "(" + g + ")"
			}
			guardExpr = strings.Join(wrapped, " || ")
		}
		s.line("#if " + guardExpr)
		for _, h := range pending {
			s.line(`#include "` + h + `"`)
		}
		s.line("#endif")
	}

	s.blank()
	s.line("#include <stdbool.h>")
	s.line("#include <stddef.h>")
	s.blank()
}

func renderTraitStructs(s *cSource, traits []resolvedTrait) {
	for i := range traits {
		rt := &traits[i]
		if !rt.instantiated || rt.contract.BindingMode != "struct" {
			continue
		}
		if rt.contract.Guard != "" {
			s.line("#if " + rt.contract.Guard)
		}
		for _, ad := range rt.adapters {
			wrapAd := ad.guard != "" && ad.guard != rt.contract.Guard
			if wrapAd {
				s.line("#if " + ad.guard)
			}
			s.linef("static %s %s(void)", ad.returnType, ad.name)
			s.line("{")
			for _, line := range ad.bodyLines {
				s.line("    " + line)
			}
			s.line("}")
			if wrapAd {
				s.line("#endif")
			}
			s.blank()
		}

		s.linef("static const %s g_platform_%s_hal = {", rt.contract.StructType, rt.contract.Name)
		activeGuard := ""
		for _, f := range rt.fields {
			if f.guard != activeGuard {
				if activeGuard != "" {
					s.line("#endif")
				}
				if f.guard != "" {
					s.line("#if " + f.guard)
				}
				activeGuard = f.guard
			}
			s.linef("    .%s = %s,", f.field, f.expr)
		}
		if activeGuard != "" {
			s.line("#endif")
		}
		s.line("};")
		if rt.contract.Guard != "" {
			s.line("#endif")
		}
		s.blank()
	}
}

func renderPlatformAndBringup(
	s *cSource,
	ctx *Context,
	hc *halContract,
	traits []resolvedTrait,
	byName map[string]resolvedTrait,
) error {
	s.linef("static const %s g_platform_instance = {", hc.PlatformStructType)
	for i := range traits {
		rt := &traits[i]
		if rt.instantiated && rt.contract.Guard != "" {
			s.line("#if " + rt.contract.Guard)
			s.linef("    .%s = %s,", rt.contract.PlatformField, rt.platformExpr)
			s.line("#endif")
		} else {
			s.linef("    .%s = %s,", rt.contract.PlatformField, rt.platformExpr)
		}
	}
	s.line("};")
	s.blank()

	type renderedStep struct {
		guard string
		line  string
	}
	var steps []renderedStep
	for _, step := range hc.BringupSteps {
		rt := byName[step.Trait]
		include := false
		switch step.Condition {
		case "always":
			if !rt.instantiated {
				return fmt.Errorf("FATAL: bringup step for '%s' has condition 'always' but trait is not instantiated", step.Trait)
			}
			include = true
		case "trait_bound":
			include = rt.instantiated
		case "init_bound":
			include = rt.instantiated && rt.boundMethods["init"] != ""
		}
		if !include {
			continue
		}
		mandLit := "false"
		if step.Mandatory {
			mandLit = "true"
		}
		initGuard := ""
		for _, f := range rt.fields {
			if f.field == "init" {
				initGuard = f.guard
				break
			}
		}
		stepGuard := rt.contract.Guard
		switch {
		case initGuard == "":
		case stepGuard == "", stepGuard == initGuard:
			stepGuard = initGuard
		default:
			stepGuard = fmt.Sprintf("(%s) && (%s)", stepGuard, initGuard)
		}
		steps = append(steps, renderedStep{
			guard: stepGuard,
			line:  fmt.Sprintf("    { %s, %s, %s },", step.KindEnum, mandLit, step.PanicSite),
		})
	}

	if len(steps) > 0 {
		s.linef("static const %s g_bringup_steps[] = {", hc.BringupStepType)
		activeGuard := ""
		for _, st := range steps {
			if st.guard != activeGuard {
				if activeGuard != "" {
					s.line("#endif")
				}
				if st.guard != "" {
					s.line("#if " + st.guard)
				}
				activeGuard = st.guard
			}
			s.line(st.line)
		}
		if activeGuard != "" {
			s.line("#endif")
		}
		s.line("};")
		s.blank()
	}

	s.linef("const %s *%s(void)", hc.PlatformStructType, hc.PlatformInitSymbol)
	s.line("{")
	if hc.Arch.EntryIRQDisableSymbol != "" {
		s.linef("    %s();", ctx.Arch.Symbols[hc.Arch.EntryIRQDisableSymbol])
	}
	if len(steps) > 0 {
		s.linef("    (void)%s(&g_platform_instance, g_bringup_steps,", hc.BringupFunction)
		s.line("                                sizeof(g_bringup_steps) / sizeof(g_bringup_steps[0]));")
	} else {
		s.linef("    (void)%s(&g_platform_instance, NULL, 0U);", hc.BringupFunction)
	}
	s.line("    return &g_platform_instance;")
	s.line("}")
	return nil
}
