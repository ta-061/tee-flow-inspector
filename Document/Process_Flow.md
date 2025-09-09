# TA静的解析システム - 処理フロー

## 全体処理フロー

```mermaid
graph TB
    Start([開始]) --> Clean[依存関係クリーンアップ]
    Clean --> P1[Phase 1-2: データベース構築と関数分類]
    P1 --> P3[Phase 3: シンク特定]
    P3 --> P4[Phase 4: 候補フロー生成]
    P4 --> P5[Phase 5: テイント解析]
    P5 --> P6[Phase 6: レポート生成]
    P6 --> End([終了])
    
    style P1 fill:#e1f5fe
    style P3 fill:#fff3e0
    style P4 fill:#f3e5f5
    style P5 fill:#fce4ec
    style P6 fill:#e8f5e9
```

## Phase 0: 依存関係クリーンアップ & ビルド

### 処理フロー

```mermaid
graph TB
    Start([開始]) --> CheckStale{古い依存関係ファイル<br/>存在?}
    
    CheckStale -->|Yes| ScanDeps[「*.d」ファイルをスキャン]
    CheckStale -->|No| TryBuild
    
    ScanDeps --> CheckPath{「/mnt/disk/toolschain」<br/>を含む?}
    CheckPath -->|Yes| DeleteFile[ファイル削除]
    CheckPath -->|No| NextFile[次のファイル]
    
    DeleteFile --> NextFile
    NextFile --> MoreFiles{他の.dファイル<br/>存在?}
    MoreFiles -->|Yes| CheckPath
    MoreFiles -->|No| TryBuild[ビルド試行開始]
    
    TryBuild --> CheckBuildSh{build.sh<br/>存在?}
    CheckBuildSh -->|Yes| RunBear1[bear -- ./build.sh]
    CheckBuildSh -->|No| CheckNdkBuild
    
    RunBear1 --> CheckDB1{compile_commands.json<br/>生成成功?}
    CheckDB1 -->|Yes| ExtractTA
    CheckDB1 -->|No| CheckNdkBuild
    
    CheckNdkBuild{ndk_build.sh<br/>存在?}
    CheckNdkBuild -->|Yes| RunBear2[bear -- ./ndk_build.sh]
    CheckNdkBuild -->|No| CheckMakefile
    
    RunBear2 --> CheckDB2{compile_commands.json<br/>生成成功?}
    CheckDB2 -->|Yes| ExtractTA
    CheckDB2 -->|No| CheckMakefile
    
    CheckMakefile{Makefile<br/>存在?}
    CheckMakefile -->|Yes| RunBear3[bear -- make]
    CheckMakefile -->|No| CheckTaMakefile
    
    RunBear3 --> CheckDB3{compile_commands.json<br/>生成成功?}
    CheckDB3 -->|Yes| ExtractTA
    CheckDB3 -->|No| CheckTaMakefile
    
    CheckTaMakefile{ta/Makefile<br/>存在?}
    CheckTaMakefile -->|Yes| RunBear4[bear -- make -C ta V=1]
    CheckTaMakefile -->|No| CheckCMake
    
    RunBear4 --> CheckDB4{compile_commands.json<br/>生成成功?}
    CheckDB4 -->|Yes| ExtractTA
    CheckDB4 -->|No| CheckCMake
    
    CheckCMake{CMakeLists.txt<br/>存在?}
    CheckCMake -->|Yes| RunCMake[cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON]
    CheckCMake -->|No| GenerateDummy
    
    RunCMake --> CheckDB5{compile_commands.json<br/>生成成功?}
    CheckDB5 -->|Yes| ExtractTA
    CheckDB5 -->|No| GenerateDummy
    
    ExtractTA[TAディレクトリの<br/>エントリを抽出]
    ExtractTA --> ValidateEntries{全ての*.cファイル<br/>が含まれている?}
    
    ValidateEntries -->|Yes| SaveDB[compile_commands.json<br/>として保存]
    ValidateEntries -->|No| GenerateDummy
    
    GenerateDummy[ダミーDB生成]
    GenerateDummy --> CollectCFiles[*.c ファイル収集]
    CollectCFiles --> CreateEntries[コンパイルエントリ作成<br/>-I&#123;ta_dir&#125;<br/>-I&#123;ta_dir&#125;/include<br/>-I&#123;devkit&#125;/include]
    CreateEntries --> SaveDB
    
    SaveDB --> End([終了])
    
    style ScanDeps fill:#ffe0b2
    style TryBuild fill:#e1f5fe
    style GenerateDummy fill:#ffccbc
    style SaveDB fill:#c8e6c9
```

## Phase 1-2: データベース構築と関数分類

### 処理フロー

```mermaid
graph TB
    Start([開始]) --> LoadDB[compile_commands.json<br/>読み込み]
    
    LoadDB --> ParseLoop[各ソースファイルを<br/>パース]
    
    ParseLoop --> NormalizeArgs[コンパイル引数を正規化<br/>-I, -D, -include等を抽出]
    
    NormalizeArgs --> AddIncludes[インクルードパス追加<br/>1. ta/include<br/>2. ta/<br/>3. devkit/include]
    
    AddIncludes --> ParseAST[libclangで<br/>AST構築]
    
    ParseAST --> CheckErrors{パースエラー?}
    CheckErrors -->|Yes| RecordError[エラー記録<br/>続行]
    CheckErrors -->|No| ExtractDecls
    
    RecordError --> NextFile{他のファイル<br/>ある?}
    
    ExtractDecls[関数・マクロ抽出]
    ExtractDecls --> WalkAST[AST走査]
    
    WalkAST --> CheckNode{ノードタイプ?}
    
    CheckNode -->|FUNCTION_DECL| ExtractFunc[関数情報抽出<br/>・name<br/>・file/line<br/>・is_definition<br/>・is_static]
    
    CheckNode -->|MACRO_DEFINITION| ExtractMacro[マクロ情報抽出<br/>・name<br/>・params<br/>・file/line]
    
    CheckNode -->|その他| NextNode[次のノード]
    
    ExtractFunc --> StoreDecl[宣言情報保存]
    ExtractMacro --> StoreDecl
    StoreDecl --> NextNode
    
    NextNode --> MoreNodes{他のノード<br/>ある?}
    MoreNodes -->|Yes| CheckNode
    MoreNodes -->|No| NextFile
    
    NextFile -->|Yes| ParseLoop
    NextFile -->|No| ClassifyPhase[分類フェーズ開始]
    
    ClassifyPhase --> CollectDefined[定義済み関数の収集]
    
    CollectDefined --> IsDefinition{is_definition<br/>== true?}
    IsDefinition -->|Yes| CheckProjectPath{プロジェクト内<br/>のファイル?}
    IsDefinition -->|No| NextDecl1
    
    CheckProjectPath -->|Yes| AddToUserDefined[ユーザ定義として記録<br/>static関数は<br/>ファイル名付きで管理]
    CheckProjectPath -->|No| NextDecl1
    
    AddToUserDefined --> NextDecl1[次の宣言]
    NextDecl1 --> MoreDecls1{他の宣言<br/>ある?}
    MoreDecls1 -->|Yes| IsDefinition
    MoreDecls1 -->|No| ClassifyDecls
    
    ClassifyDecls[宣言の分類]
    ClassifyDecls --> ProcessDecl[各宣言を処理]
    
    ProcessDecl --> CheckKind{宣言の種類?}
    
    CheckKind -->|関数| CheckFuncDef{定義済み?}
    CheckFuncDef -->|Yes in Project| SkipForward[前方宣言として<br/>スキップ]
    CheckFuncDef -->|No| AddExternal1[外部関数として<br/>追加]
    
    CheckKind -->|マクロ| CheckMacroLoc{マクロの場所?}
    CheckMacroLoc -->|Project内| CheckIncludeDir{include/配下?}
    CheckMacroLoc -->|Project外| AddExternal2[外部マクロとして<br/>追加]
    
    CheckIncludeDir -->|Yes| AddExternal3[外部APIとして<br/>追加]
    CheckIncludeDir -->|No| CheckMacroType{関数マクロ?}
    
    CheckMacroType -->|Yes| AddExternal4[外部として追加]
    CheckMacroType -->|No| SkipConstMacro[定数マクロ<br/>スキップ]
    
    SkipForward --> NextDecl2
    AddExternal1 --> NextDecl2
    AddExternal2 --> NextDecl2
    AddExternal3 --> NextDecl2
    AddExternal4 --> NextDecl2
    SkipConstMacro --> NextDecl2
    
    NextDecl2[次の宣言] --> MoreDecls2{他の宣言<br/>ある?}
    MoreDecls2 -->|Yes| ProcessDecl
    MoreDecls2 -->|No| Deduplicate
    
    Deduplicate[重複排除]
    Deduplicate --> SaveResults[結果保存<br/>phase12.json]
    
    SaveResults --> End([終了])
    
    style LoadDB fill:#e1f5fe
    style ParseAST fill:#fff9c4
    style ClassifyPhase fill:#f3e5f5
    style SaveResults fill:#c8e6c9
```

## Phase 3: シンク特定

### 処理フロー

```mermaid
graph TB
    Start([開始]) --> LoadPhase12[phase12.json<br/>読み込み]
    
    LoadPhase12 --> ExtractExternal[外部宣言リスト<br/>抽出]
    
    ExtractExternal --> ScanUserFuncs[ユーザ定義関数を<br/>スキャン]
    
    ScanUserFuncs --> SkipEntry{エントリポイント<br/>関数?}
    SkipEntry -->|Yes| NextUserFunc
    SkipEntry -->|No| ExtractCode[関数コード抽出]
    
    ExtractCode --> ParseCalls[関数呼び出しを<br/>正規表現で抽出]
    
    ParseCalls --> CheckExternal{外部関数<br/>呼び出し?}
    CheckExternal -->|Yes| AddToCallList[呼び出しリストに<br/>追加]
    CheckExternal -->|No| NextCall
    
    AddToCallList --> NextCall[次の呼び出し]
    NextCall --> MoreCalls{他の呼び出し<br/>ある?}
    MoreCalls -->|Yes| CheckExternal
    MoreCalls -->|No| NextUserFunc
    
    NextUserFunc[次のユーザ関数] --> MoreUserFuncs{他のユーザ<br/>関数ある?}
    MoreUserFuncs -->|Yes| SkipEntry
    MoreUserFuncs -->|No| InitAnalysis
    
    InitAnalysis[シンク解析開始]
    InitAnalysis --> CheckRAG{RAG有効?}
    
    CheckRAG -->|Yes| InitRAGClient[RAGクライアント<br/>初期化]
    CheckRAG -->|No| InitLLM
    
    InitRAGClient --> BuildIndex{インデックス<br/>構築済み?}
    BuildIndex -->|No| BuildVectorStore[ベクトルストア<br/>構築]
    BuildIndex -->|Yes| InitLLM
    
    BuildVectorStore --> InitLLM[LLMクライアント<br/>初期化]
    
    InitLLM --> ConfigureRetry[リトライハンドラー<br/>設定]
    
    ConfigureRetry --> AnalyzeLoop[各外部関数を<br/>解析]
    
    AnalyzeLoop --> UseRAG{RAG使用?}
    
    UseRAG -->|Yes| SearchRAG[RAGで関連情報<br/>検索]
    UseRAG -->|No| PreparePrompt
    
    SearchRAG --> SelectPrompt{RAG結果<br/>あり?}
    SelectPrompt -->|Yes| LoadRAGPrompt[RAG用プロンプト<br/>読み込み]
    SelectPrompt -->|No| LoadBasicPrompt[基本プロンプト<br/>読み込み]
    
    LoadRAGPrompt --> FormatPrompt[プロンプト<br/>フォーマット]
    LoadBasicPrompt --> FormatPrompt
    PreparePrompt[プロンプト準備] --> FormatPrompt
    
    FormatPrompt --> CallLLM[LLM呼び出し<br/>（リトライ付き）]
    
    CallLLM --> ParseResponse[レスポンス解析<br/>正規表現パターン<br/>マッチング]
    
    ParseResponse --> ExtractSinks[シンク情報抽出<br/>・function<br/>・param_index<br/>・reason]
    
    ExtractSinks --> RecordTime[解析時間記録]
    
    RecordTime --> NextFunc[次の外部関数]
    NextFunc --> MoreFuncs{他の関数<br/>ある?}
    MoreFuncs -->|Yes| AnalyzeLoop
    MoreFuncs -->|No| Dedup
    
    Dedup[重複排除<br/>&#40;name, param_index&#41;で<br/>ユニーク化]
    
    Dedup --> CollectStats[統計情報収集]
    
    CollectStats --> CheckTokens{トークン追跡<br/>有効?}
    CheckTokens -->|Yes| GetTokenStats[トークン使用量<br/>取得]
    CheckTokens -->|No| SaveResults
    
    GetTokenStats --> SaveResults[結果保存<br/>sinks.json]
    
    SaveResults --> End([終了])
    
    style LoadPhase12 fill:#e1f5fe
    style InitRAGClient fill:#fff3e0
    style CallLLM fill:#ffebee
    style SaveResults fill:#c8e6c9
```

## Phase 4: 候補フロー生成

### 処理フロー

```mermaid
graph TB
    Start([開始]) --> LoadData[必要データ読み込み<br/>・ta_sinks.json<br/>・ta_phase12.json<br/>・compile_commands.json]
    
    LoadData --> ExtractMacros[phase12から<br/>マクロ情報抽出]
    
    ExtractMacros --> CheckDebugMacros{デバッグマクロ<br/>を含める?}
    CheckDebugMacros -->|No| FilterMacros[デバッグマクロ除外<br/>・MSG系パターン<br/>・trace.h定義]
    CheckDebugMacros -->|Yes| KeepAllMacros[全マクロ保持]
    
    FilterMacros --> ParseSources
    KeepAllMacros --> ParseSources[全ソースファイル<br/>パース]
    
    ParseSources --> ParseLoop[各ソースファイル<br/>処理]
    ParseLoop --> AdjustArgs[コンパイル引数調整<br/>・不要オプション除去<br/>・インクルードパス追加]
    
    AdjustArgs --> BuildAST[libclangで<br/>AST構築]
    
    BuildAST --> NextSource{次のソース<br/>ある?}
    NextSource -->|Yes| ParseLoop
    NextSource -->|No| BuildCallGraph
    
    BuildCallGraph[コールグラフ構築]
    BuildCallGraph --> CollectFuncDefs[関数定義収集<br/>・位置情報<br/>・範囲情報]
    
    CollectFuncDefs --> CollectCallEdges[呼び出しエッジ収集<br/>・caller/callee<br/>・呼び出し行番号]
    
    CollectCallEdges --> DetectSinks[シンク呼び出し検出]
    
    DetectSinks --> WalkAST[AST走査]
    WalkAST --> CheckCallExpr{関数呼び出し?}
    
    CheckCallExpr -->|Yes| CheckSinkFunc{シンク関数?}
    CheckCallExpr -->|No| NextNode
    
    CheckSinkFunc -->|Yes| RecordSinkCall[シンク呼び出し記録<br/>・位置情報<br/>・含有関数<br/>・引数情報]
    CheckSinkFunc -->|No| CheckMacroExpand{マクロ展開<br/>trace_printf?}
    
    CheckMacroExpand -->|Yes| RestoreOriginal[元のマクロ名<br/>復元]
    CheckMacroExpand -->|No| NextNode
    
    RestoreOriginal --> RecordSinkCall
    RecordSinkCall --> NextNode[次のノード]
    
    NextNode --> MoreNodes{他のノード<br/>ある?}
    MoreNodes -->|Yes| CheckCallExpr
    MoreNodes -->|No| TraceChains
    
    TraceChains[チェイン追跡]
    TraceChains --> BuildReverseIndex[逆インデックス構築<br/>callee → callers]
    
    BuildReverseIndex --> TraceEachSink[各シンク呼び出し<br/>を追跡]
    
    TraceEachSink --> FindContaining[シンク含有関数<br/>特定]
    
    FindContaining --> TraceBackward[逆方向追跡<br/>（再帰的）]
    
    TraceBackward --> ReachSource{ソース関数<br/>到達?}
    ReachSource -->|Yes| RecordPath[パス記録]
    ReachSource -->|No| CheckCallers{呼び出し元<br/>ある?}
    
    CheckCallers -->|Yes| TraceBackward
    CheckCallers -->|No| DiscardPath[パス破棄]
    
    RecordPath --> ConvertToFlow[フローに変換<br/>・関数チェイン<br/>・行番号リスト]
    DiscardPath --> NextSinkCall
    
    ConvertToFlow --> NextSinkCall[次のシンク]
    NextSinkCall --> MoreSinks{他のシンク<br/>ある?}
    MoreSinks -->|Yes| TraceEachSink
    MoreSinks -->|No| OptimizeFlows
    
    OptimizeFlows[フロー最適化]
    OptimizeFlows --> MergeParams[同一シンク・同一チェインの<br/>param_indexマージ]
    
    MergeParams --> RemoveDups[重複除去]
    
    RemoveDups --> RemoveSubchains[サブチェイン除去<br/>（同一行のみ）]
    
    RemoveSubchains --> MergeSameLine[同一関数内の<br/>複数行シンクマージ]
    
    MergeSameLine --> SaveResults[結果保存<br/>candidate_flows.json]
    
    SaveResults --> End([終了])
    
    style LoadData fill:#e1f5fe
    style BuildCallGraph fill:#fff3e0
    style DetectSinks fill:#f3e5f5
    style TraceChains fill:#fce4ec
    style OptimizeFlows fill:#e8f5e9
    style SaveResults fill:#c8e6c9
```

## Phase 5: テイント解析と脆弱性検査
### 1. システム全体フロー

```mermaid
graph TB
    Start[開始: taint_analyzer.py]
    Start --> ParseArgs[コマンドライン引数解析]
    ParseArgs --> LoadInput[入力データ読み込み<br/>- flows.json<br/>- phase12.json]
    
    LoadInput --> InitLLM[LLMクライアント初期化<br/>UnifiedLLMClient]
    InitLLM --> SetupPrompt[システムプロンプト設定<br/>4つのモード対応]
    
    SetupPrompt --> InitComponents[コンポーネント初期化<br/>- CodeExtractor<br/>- VulnerabilityUtils<br/>- TaintAnalyzer]
    
    InitComponents --> AnalyzeFlows[全フロー解析開始]
    
    AnalyzeFlows --> FlowLoop{各フローを<br/>順次処理}
    
    FlowLoop --> AnalyzeSingle[単一フロー解析]
    AnalyzeSingle --> CheckCache[キャッシュチェック]
    
    CheckCache --> CacheHit{キャッシュ<br/>ヒット?}
    CacheHit -->|Yes| RestoreState[状態復元]
    CacheHit -->|No| AnalyzeFunctions[関数チェーン解析]
    
    RestoreState --> AnalyzeFunctions
    AnalyzeFunctions --> FuncLoop{各関数を<br/>順次解析}
    
    FuncLoop --> ExtractCode[関数コード抽出]
    ExtractCode --> CallLLM[LLM呼び出し<br/>テイント解析]
    CallLLM --> ParseResponse[統合パーサーで<br/>レスポンス解析]
    ParseResponse --> UpdateCache[キャッシュ更新]
    
    UpdateCache --> NextFunc{次の関数<br/>あり?}
    NextFunc -->|Yes| FuncLoop
    NextFunc -->|No| VulnAnalysis[脆弱性判定]
    
    VulnAnalysis --> ConsistencyCheck[整合性チェック]
    ConsistencyCheck --> CollectFindings[Findings収集]
    
    CollectFindings --> NextFlow{次のフロー<br/>あり?}
    NextFlow -->|Yes| FlowLoop
    NextFlow -->|No| MergeFindings[Findings統合]
    
    MergeFindings --> GenerateReport[レポート生成]
    GenerateReport --> SaveOutput[結果保存<br/>- JSON<br/>- Summary]
    SaveOutput --> End[終了]
```

### 2. プロンプト設定フロー

```mermaid
graph TB
    SetupStart[setup_system_prompt開始]
    SetupStart --> DetermineMode{モード判定}
    
    DetermineMode --> HybridRAG[Hybrid + RAG]
    DetermineMode --> HybridNoRAG[Hybrid - RAG]
    DetermineMode --> LLMOnlyRAG[LLM-only + RAG]
    DetermineMode --> LLMOnlyNoRAG[LLM-only - RAG]
    
    HybridRAG --> LoadDiting1[DITINGルール読込]
    LoadDiting1 --> BuildHints1[CodeQLヒント生成]
    BuildHints1 --> InitRAG1[RAGクライアント初期化]
    InitRAG1 --> LoadTemplate1[テンプレート読込<br/>hybrid/with_rag/]
    
    HybridNoRAG --> LoadDiting2[DITINGルール読込]
    LoadDiting2 --> BuildHints2[CodeQLヒント生成]
    BuildHints2 --> LoadTemplate2[テンプレート読込<br/>hybrid/no_rag/]
    
    LLMOnlyRAG --> BuildHints3[CodeQLヒント生成]
    BuildHints3 --> InitRAG3[RAGクライアント初期化]
    InitRAG3 --> LoadTemplate3[テンプレート読込<br/>llm_only/with_rag/]
    
    LLMOnlyNoRAG --> BuildHints4[CodeQLヒント生成]
    BuildHints4 --> LoadTemplate4[テンプレート読込<br/>llm_only/no_rag/]
    
    LoadTemplate1 --> ReplacePlaceholders[プレースホルダー置換<br/>- diting_rules_json<br/>- RULE_HINTS_BLOCK]
    LoadTemplate2 --> ReplacePlaceholders
    LoadTemplate3 --> ReplacePlaceholders
    LoadTemplate4 --> ReplacePlaceholders
    
    ReplacePlaceholders --> ValidatePrompt[プロンプト検証]
    ValidatePrompt --> ReturnPrompt[プロンプトとメタデータ返却]
```

### 3. 関数解析フロー

```mermaid
graph TB
    FuncStart[FunctionAnalyzer.analyze_function開始]
    FuncStart --> ExtractFunc[関数コード抽出<br/>CodeExtractor使用]
    
    ExtractFunc --> BuildContext[呼び出しコンテキスト構築]
    BuildContext --> GenPrompt[プロンプト生成]
    
    GenPrompt --> StartPrompt{位置=0?}
    StartPrompt -->|Yes| GetStartPrompt[get_start_prompt]
    StartPrompt -->|No| GetMiddlePrompt[get_middle_prompt]
    
    GetStartPrompt --> AddToConv[会話履歴に追加]
    GetMiddlePrompt --> CheckRAG{RAG有効?}
    
    CheckRAG -->|Yes| SearchRAG[RAGコンテキスト取得]
    CheckRAG -->|No| AddToConv
    SearchRAG --> AddToConv
    
    AddToConv --> CallLLMFunc[LLMHandler.ask_with_handler]
    
    CallLLMFunc --> ValidateResp[SmartResponseValidator<br/>早期検証と自動修復]
    
    ValidateResp --> ParseResp[UnifiedLLMResponseParser<br/>統合パース処理]
    
    ParseResp --> ParseSuccess{パース<br/>成功?}
    ParseSuccess -->|No| RetryDecision[IntelligentRetryStrategy<br/>リトライ判定]
    
    RetryDecision --> ShouldRetry{リトライ<br/>すべき?}
    ShouldRetry -->|Yes| CreateCorrection[修正プロンプト生成]
    CreateCorrection --> CallLLMFunc
    ShouldRetry -->|No| ProcessResult
    
    ParseSuccess -->|Yes| ProcessResult[結果処理<br/>- テイント情報抽出<br/>- Findings抽出<br/>- 推論トレース更新]
    
    ProcessResult --> FuncEnd[終了]
```

### 4. 統合パーサー処理フロー

```mermaid
graph TB
    ParseStart[UnifiedLLMResponseParser開始]
    ParseStart --> CheckCache{キャッシュ<br/>確認}
    
    CheckCache -->|Hit| ReturnCached[キャッシュ結果返却]
    CheckCache -->|Miss| CheckType{入力タイプ<br/>判定}
    
    CheckType -->|Dict| HandleDict[辞書形式処理]
    CheckType -->|String| SplitLines[スマート行分割<br/>JSON構造考慮]
    
    SplitLines --> ProcessLine1[Line1処理]
    ProcessLine1 --> Phase1{フェーズ<br/>判定}
    
    Phase1 -->|start/middle| ParseTaint[テイントJSON解析]
    Phase1 -->|end| ParseVuln[脆弱性判定解析]
    
    ParseTaint --> ProcessLine2[Line2処理]
    ParseVuln --> ProcessLine2
    
    ProcessLine2 --> Phase2{フェーズ<br/>判定}
    Phase2 -->|start/middle| ParseFindings[FINDINGS解析]
    Phase2 -->|end| ParseDetails[詳細JSON解析]
    
    ParseFindings --> CheckLine3{3行目<br/>あり?}
    ParseDetails --> CheckLine3
    
    CheckLine3 -->|Yes & end| ParseEndFindings[END_FINDINGS解析]
    CheckLine3 -->|No| ValidateResult[結果検証]
    ParseEndFindings --> ValidateResult
    
    ValidateResult --> Success{検証<br/>成功?}
    Success -->|Yes| UpdateCache[キャッシュ更新]
    Success -->|No| RecordError[エラー記録]
    
    UpdateCache --> ReturnResult[結果返却]
    RecordError --> ReturnResult
    
    HandleDict --> ExtractFields[フィールド抽出]
    ExtractFields --> ReturnResult
```

### 5. 脆弱性判定フロー

```mermaid
graph TB
    VulnStart[VulnerabilityAnalyzer開始]
    VulnStart --> GenEndPrompt[get_end_prompt]
    
    GenEndPrompt --> CallLLMVuln[LLMに脆弱性判定要求]
    CallLLMVuln --> ValidateVuln[レスポンス検証<br/>SmartResponseValidator]
    
    ValidateVuln --> ParseVulnResp[統合パーサーで解析]
    ParseVulnResp --> ExtractDecision[脆弱性判定抽出]
    
    ExtractDecision --> ExtractEndFindings[END_FINDINGS抽出]
    
    ExtractEndFindings --> CheckEmpty{END_FINDINGS<br/>空?}
    CheckEmpty -->|Yes & Vuln| RecoveryAttempt[Findings救済試行]
    CheckEmpty -->|No| CheckTaintFlow
    
    RecoveryAttempt --> RequestFindings[LLMに再要求]
    RequestFindings --> CheckTaintFlow[テイントフロー検証]
    
    CheckTaintFlow --> ValidFlow{有効な<br/>フロー?}
    ValidFlow -->|No & Vuln| Reevaluate[整合性再評価]
    ValidFlow -->|Yes| CheckFindingsConsist
    
    Reevaluate --> UpdateDecision[判定更新]
    UpdateDecision --> CheckFindingsConsist[Findings整合性チェック]
    
    CheckFindingsConsist --> Consistent{整合?}
    Consistent -->|No| AdjustFindings[Findings調整<br/>- 誤検出除外<br/>- 救済抽出]
    Consistent -->|Yes| BuildResult
    
    AdjustFindings --> BuildResult[最終結果構築]
    BuildResult --> VulnEnd[終了]
```

### 6. LLM通信とエラー処理フロー

```mermaid
graph TB
    LLMStart[LLMHandler.ask_with_handler開始]
    LLMStart --> BuildFullContext[完全コンテキスト構築]
    
    BuildFullContext --> RetryLoop{リトライ<br/>ループ}
    
    RetryLoop --> CallAPI[LLM API呼び出し]
    CallAPI --> CheckEmpty{空レスポンス?}
    
    CheckEmpty -->|Yes| DiagnoseEmpty[ResponseDiagnostics<br/>空レスポンス診断]
    CheckEmpty -->|No| CheckError{エラー?}
    
    DiagnoseEmpty --> LogError1[エラーログ記録]
    
    CheckError -->|Yes| AnalyzeError[LLMErrorAnalyzer<br/>エラー分析]
    CheckError -->|No| ReturnSuccess[成功レスポンス返却]
    
    AnalyzeError --> LogError2[エラーログ記録]
    
    LogError1 --> CheckRetry{リトライ<br/>可能?}
    LogError2 --> CheckRetry
    
    CheckRetry -->|Yes & attempts < max| WaitBackoff[バックオフ待機]
    WaitBackoff --> RetryLoop
    
    CheckRetry -->|No| HandleFatal[致命的エラー処理]
    HandleFatal --> SaveErrorLog[エラーログ保存]
    SaveErrorLog --> ExitProgram[プログラム終了]
```

### 7. キャッシュとFindings統合フロー

```mermaid
graph TB
    CacheStart[PrefixCache処理]
    CacheStart --> CheckPrefix{接頭辞<br/>確認}
    
    CheckPrefix --> SearchCache[最長一致検索]
    SearchCache --> Found{見つかった?}
    
    Found -->|Yes| RestoreConv[会話履歴復元]
    Found -->|No| StartFresh[新規開始]
    
    RestoreConv --> ContinueAnalysis[解析継続]
    StartFresh --> ContinueAnalysis
    
    ContinueAnalysis --> SavePrefix[接頭辞保存]
    
    subgraph Findings統合
        MergeStart[FindingsMerger開始]
        MergeStart --> GroupFindings[グループ化<br/>- file<br/>- line<br/>- sink<br/>- rule]
        
        GroupFindings --> ProcessGroups{各グループ<br/>処理}
        
        ProcessGroups --> CheckDup{重複?}
        CheckDup -->|Yes| SelectBest[代表選択<br/>end優先]
        CheckDup -->|No| KeepSingle[単一保持]
        
        SelectBest --> MergeReasons[理由統合]
        KeepSingle --> AddToFinal
        MergeReasons --> AddToFinal[最終リストに追加]
        
        AddToFinal --> NextGroup{次の<br/>グループ?}
        NextGroup -->|Yes| ProcessGroups
        NextGroup -->|No| ReturnMerged[統合結果返却]
    end
```

## Phase 6: HTMLレポート生成

### 処理フロー

```mermaid
graph TB
    Start([開始]) --> LoadInputs[入力ファイル読込<br/>・vulnerabilities.json<br/>・phase12.json<br/>・sinks.json 任意]
    
    LoadInputs --> CheckLogFile{ログファイル<br/>存在?}
    
    CheckLogFile -->|Yes| ParseLog[ログ解析<br/>taint_analysis_log.txt]
    CheckLogFile -->|No| EmptyConv[空の対話履歴]
    
    ParseLog --> ExtractConv[対話履歴抽出<br/>・チェーン名検出<br/>・プロンプト/応答<br/>・整合性メッセージ]
    EmptyConv --> ExtractConv
    
    ExtractConv --> LoadFlows{candidate_flows<br/>存在?}
    
    LoadFlows -->|Yes| ExtractAllChains[全チェーン抽出<br/>・解析済みチェーン<br/>・未解析チェーン]
    LoadFlows -->|No| UseVulnChains[脆弱性チェーンのみ使用]
    
    ExtractAllChains --> CalculateStats
    UseVulnChains --> CalculateStats
    
    CalculateStats[統計情報計算<br/>・チェーン数<br/>・関数数<br/>・LLM呼び出し数]
    
    CalculateStats --> MapVulnToChain[脆弱性マッピング<br/>チェーン名→脆弱性情報]
    
    MapVulnToChain --> GenerateChainHTML[チェーンHTML生成（ループ）]
    
    GenerateChainHTML --> CheckConversation{対話履歴<br/>あり?}
    
    CheckConversation -->|Yes| FormatMessages[メッセージ整形<br/>・JSON検出/整形<br/>・コードブロック処理<br/>・HTMLエスケープ]
    CheckConversation -->|No| NoAnalysisHTML[未解析表示]
    
    FormatMessages --> CheckVuln{脆弱性<br/>あり?}
    NoAnalysisHTML --> CheckVuln
    
    CheckVuln -->|Yes| AddVulnInfo[脆弱性情報追加<br/>・タイプ<br/>・深刻度<br/>・説明]
    CheckVuln -->|No| SafeStatus[安全ステータス]
    
    AddVulnInfo --> CreateChainItem
    SafeStatus --> CreateChainItem
    
    CreateChainItem[チェーン要素作成<br/>・フロー表示<br/>・対話履歴<br/>・折りたたみ機能]
    
    CreateChainItem --> MoreChains{他のチェーン<br/>ある?}
    MoreChains -->|Yes| GenerateChainHTML
    MoreChains -->|No| GenerateSections
    
    GenerateSections[セクション生成]
    
    GenerateSections --> GenTimeline[実行タイムライン生成<br/>・Phase3時間<br/>・Phase5時間<br/>・プログレスバー]
    
    GenTimeline --> GenTokenUsage[トークン使用量生成<br/>・シンク特定<br/>・テイント解析<br/>・合計統計]
    
    GenTokenUsage --> GenSinksSummary[シンクサマリー生成<br/>・特定シンク一覧<br/>・判定方法（LLM/Rule）<br/>・パラメータ情報]
    
    GenSinksSummary --> GenVulnDetails[脆弱性詳細生成<br/>・検出脆弱性リスト<br/>・深刻度表示<br/>・場所情報]
    
    GenVulnDetails --> GenFindings[Findings生成<br/>・インライン検出<br/>・カテゴリ分類<br/>・ルールマッチ]
    
    GenFindings --> LoadTemplate[HTMLテンプレート読込<br/>・CSS/JS組み込み<br/>・プレースホルダー定義]
    
    LoadTemplate --> FillTemplate[テンプレート埋込<br/>・プロジェクト情報<br/>・統計データ<br/>・各セクションHTML]
    
    FillTemplate --> HandlePlaceholder{プレースホルダー<br/>エラー?}
    
    HandlePlaceholder -->|Yes| AddDefault[デフォルト値設定<br/>・N/A埋込<br/>・再試行]
    HandlePlaceholder -->|No| GenerateHTML
    
    AddDefault --> RetryFill[埋込再試行]
    RetryFill --> CheckRetry{成功?}
    
    CheckRetry -->|Yes| GenerateHTML
    CheckRetry -->|No| MinimalHTML[最小HTML生成<br/>・エラーメッセージ]
    
    GenerateHTML[完全HTML生成]
    
    GenerateHTML --> SaveHTML[HTMLファイル保存]
    MinimalHTML --> SaveHTML
    
    SaveHTML --> AddAssets[アセット処理<br/>・styles.css<br/>・script.js<br/>・埋込/外部参照]
    
    AddAssets --> DisplaySummary[サマリー表示<br/>・保存先パス<br/>・検出数<br/>・実行時間]
    
    DisplaySummary --> End([終了])
    
    style LoadInputs fill:#e1f5fe
    style ParseLog fill:#fff3e0
    style GenerateSections fill:#f3e5f5
    style LoadTemplate fill:#fce4ec
    style SaveHTML fill:#e8f5e9
```

### サブプロセス詳細

#### ログ解析プロセス
```mermaid
graph TB
    LogFile[taint_analysis_log.txt] --> ReadContent[ファイル読込<br/>UTF-8/ignore errors]
    
    ReadContent --> ScanLines[行スキャン]
    
    ScanLines --> DetectChain{チェーン開始<br/>検出?}
    
    DetectChain -->|"Analyzing chain:"| SavePrevious[前チェーン保存]
    DetectChain -->|No| CheckSection
    
    SavePrevious --> ExtractChainName[チェーン名抽出<br/>正規表現マッチ]
    
    ExtractChainName --> InitChain[チェーン初期化<br/>・会話リスト<br/>・セクション情報]
    
    CheckSection[セクション判定]
    CheckSection --> IsFuncSection{Function<br/>セクション?}
    CheckSection --> IsVulnSection{Vulnerability<br/>セクション?}
    CheckSection --> IsPrompt{### Prompt?}
    CheckSection --> IsResponse{### Response?}
    
    IsFuncSection -->|Yes| SetFuncContext[関数コンテキスト設定]
    IsVulnSection -->|Yes| SetVulnContext[脆弱性コンテキスト設定]
    
    IsPrompt -->|Yes| CollectPrompt[プロンプト収集<br/>・複数行対応<br/>・終了条件判定]
    
    CollectPrompt --> AddUserMsg[userメッセージ追加]
    
    IsResponse -->|Yes| CollectResponse[レスポンス収集<br/>・複数行対応<br/>・セクション境界]
    
    CollectResponse --> AddAssistantMsg[assistantメッセージ追加]
    
    SetFuncContext --> NextLine
    SetVulnContext --> NextLine
    AddUserMsg --> NextLine
    AddAssistantMsg --> NextLine
    
    NextLine[次の行へ] --> MoreLines{他の行<br/>ある?}
    MoreLines -->|Yes| ScanLines
    MoreLines -->|No| SaveFinal[最終チェーン保存]
    
    SaveFinal --> ReturnConv[対話履歴辞書返却]
```

#### HTMLフォーマット処理
```mermaid
graph TB
    Message[メッセージ内容] --> EscapeHTML[HTMLエスケープ]
    
    EscapeHTML --> DetectJSON{JSON検出?}
    
    DetectJSON -->|Yes| ParseJSON[JSON解析]
    DetectJSON -->|No| DetectCode
    
    ParseJSON --> FormatJSON[JSON整形<br/>・インデント<br/>・構文ハイライト]
    
    FormatJSON --> WrapPre[preタグでラップ]
    
    DetectCode[コードブロック検出]
    DetectCode --> HasCodeBlock{```あり?}
    
    HasCodeBlock -->|Yes| ExtractCode[コード抽出]
    HasCodeBlock -->|No| DetectInline
    
    ExtractCode --> ApplyHighlight[構文ハイライト<br/>・言語判定<br/>・色付け]
    
    DetectInline[インラインコード検出]
    DetectInline --> HasBacktick{`あり?}
    
    HasBacktick -->|Yes| WrapCode[codeタグでラップ]
    HasBacktick -->|No| ProcessNewlines
    
    WrapPre --> MergeContent
    ApplyHighlight --> MergeContent
    WrapCode --> MergeContent
    
    ProcessNewlines[改行処理<br/>brタグ変換]
    
    ProcessNewlines --> MergeContent[コンテンツ統合]
    
    MergeContent --> ReturnHTML[HTML文字列返却]
```

#### 統計計算プロセス
```mermaid
graph TB
    Input[入力データ] --> CountChains[チェーン数計算]
    
    CountChains --> FromConv{対話履歴<br/>あり?}
    
    FromConv -->|Yes| UseConvCount[対話履歴数使用]
    FromConv -->|No| UseVulnCount[脆弱性数使用]
    
    UseConvCount --> ExtractUnique
    UseVulnCount --> ExtractUnique
    
    ExtractUnique[ユニークチェーン抽出]
    ExtractUnique --> FromVulns[脆弱性から抽出]
    ExtractUnique --> FromConvs[対話履歴から抽出]
    
    FromVulns --> MergeUnique[重複除去<br/>Set使用]
    FromConvs --> MergeUnique
    
    MergeUnique --> CountFunctions[関数数計算<br/>チェーン分割]
    
    CountFunctions --> GetLLMCalls[LLM呼び出し数取得]
    
    GetLLMCalls --> FromStats{統計情報<br/>あり?}
    
    FromStats -->|Yes| UseStatCalls[統計値使用]
    FromStats -->|No| EstimateFromTokens[トークン数から推定]
    
    EstimateFromTokens --> CheckSinks{シンクデータ<br/>あり?}
    
    CheckSinks -->|Yes| AddSinkCalls[シンク呼び出し追加]
    CheckSinks -->|No| FinalStats
    
    UseStatCalls --> FinalStats
    AddSinkCalls --> FinalStats
    
    FinalStats[最終統計作成]
    FinalStats --> ReturnStats[統計辞書返却]
```

### レポート構成要素

#### 脆弱性レポート構造
```mermaid
graph TB
    Report[レポート] --> Header[ヘッダー<br/>・タイトル<br/>・生成日時<br/>・バージョン]
    
    Report --> Statistics[統計セクション<br/>・解析モード<br/>・実行時間<br/>・検出数]
    
    Report --> Vulnerabilities[脆弱性セクション]
    Vulnerabilities --> VulnItem[各脆弱性]
    
    VulnItem --> Chain[チェイン情報<br/>・関数フロー<br/>・呼び出し順序]
    
    VulnItem --> SinkInfo[シンク情報<br/>・関数名<br/>・ファイル<br/>・行番号]
    
    VulnItem --> TaintFlow[テイントフロー<br/>・各ステップ<br/>・伝播状態<br/>・検証結果]
    
    VulnItem --> Evidence[証拠<br/>・コード片<br/>・rule_matches<br/>・FINDINGS]
    
    Report --> FindingsList[Findings一覧]
    FindingsList --> ByCategory[カテゴリ別<br/>・UO<br/>・WIV<br/>・SMO]
    
    FindingsList --> ByFile[ファイル別<br/>・グループ化<br/>・行番号順]
    
    FindingsList --> ByPhase[フェーズ別<br/>・start<br/>・middle<br/>・end]
    
    Report --> Recommendations[推奨事項<br/>・修正優先度<br/>・対策方法<br/>・参考情報]
```

#### 統計ダッシュボード
```mermaid
graph LR
    Stats[統計情報] --> Performance[パフォーマンス]
    Performance --> Time[時間<br/>・総時間<br/>・平均時間]
    Performance --> Tokens[トークン<br/>・使用量<br/>・コスト推定]
    
    Stats --> Quality[品質指標]
    Quality --> Coverage[カバレッジ<br/>・解析フロー数<br/>・成功率]
    Quality --> Accuracy[精度<br/>・整合性<br/>・降格率]
    
    Stats --> Efficiency[効率性]
    Efficiency --> Cache[キャッシュ<br/>・ヒット率<br/>・削減効果]
    Efficiency --> Retry[リトライ<br/>・成功率<br/>・回数]
```

# 番外編
## RAG + LLM 処理フロー

### 1. 初期化フェーズ

```mermaid
graph TB
    Start([開始]) --> InitRAG[TEERAGClient初期化]
    
    InitRAG --> InitComponents[コンポーネント初期化]
    InitComponents --> InitLoader[DocumentLoader初期化<br/>・PDF格納ディレクトリ設定]
    InitComponents --> InitProcessor[TextProcessor初期化<br/>・チャンクサイズ: 1000<br/>・オーバーラップ: 200]
    InitComponents --> InitStore[VectorStore初期化<br/>・埋め込みモデル設定<br/>・永続化ディレクトリ設定]
    InitComponents --> InitRetriever[Retriever初期化<br/>・検索戦略設定]
    
    InitLoader --> CheckIndex
    InitProcessor --> CheckIndex
    InitStore --> CheckIndex
    InitRetriever --> CheckIndex
    
    CheckIndex{既存インデックス<br/>存在?}
    CheckIndex -->|Yes| LoadIndex[インデックス読み込み<br/>・メタデータ復元<br/>・統計情報復元]
    CheckIndex -->|No| WaitBuild[build_index&#40;&#41;<br/>実行待機]
    
    LoadIndex --> Ready([準備完了])
    WaitBuild --> Ready
    
    style InitRAG fill:#e1f5fe
    style Ready fill:#c8e6c9
```

### 2. インデックス構築フェーズ

```mermaid
graph TB
    BuildStart([build_index開始]) --> LoadPDFs[PDFドキュメント読み込み]
    
    LoadPDFs --> ProcessPDF[各PDFファイル処理]
    ProcessPDF --> TryPDFPlumber{pdfplumber<br/>試行}
    
    TryPDFPlumber -->|成功| ExtractText1[テキスト抽出]
    TryPDFPlumber -->|失敗| TryPyPDF2{PyPDF2<br/>試行}
    
    TryPyPDF2 -->|成功| ExtractText2[テキスト抽出]
    TryPyPDF2 -->|失敗| SkipFile[ファイルスキップ]
    
    ExtractText1 --> AddMetadata[メタデータ付与<br/>・ページ番号<br/>・ドキュメントタイプ<br/>・ファイル名]
    ExtractText2 --> AddMetadata
    
    AddMetadata --> ExtractAPIs[API関数情報抽出<br/>・TEE_*<br/>・TEEC_*<br/>・TA_*]
    
    ExtractAPIs --> NextPDF{次のPDF<br/>ある?}
    SkipFile --> NextPDF
    NextPDF -->|Yes| ProcessPDF
    NextPDF -->|No| TextProcessing
    
    TextProcessing[テキスト処理開始]
    TextProcessing --> CleanText[テキストクリーニング<br/>・空白正規化<br/>・改行正規化<br/>・不要記号除去]
    
    CleanText --> CheckAPI{API定義<br/>含む?}
    
    CheckAPI -->|Yes| ExtractAPIChunks[API定義チャンク抽出<br/>・個別チャンク化<br/>・パラメータ解析<br/>・戻り値抽出]
    CheckAPI -->|No| RegularChunks
    
    ExtractAPIChunks --> RegularChunks[通常チャンク分割<br/>・1000文字単位<br/>・200文字オーバーラップ]
    
    RegularChunks --> ChromaNormalize[ChromaDB正規化<br/>・メタデータ型変換<br/>・リスト→文字列<br/>・辞書→フラット化]
    
    ChromaNormalize --> RemoveDuplicates[重複チャンク除去]
    
    RemoveDuplicates --> CreateVectors[ベクトル生成<br/>・埋め込みモデル適用<br/>・sentence-transformers]
    
    CreateVectors --> StoreVectors{ストアタイプ?}
    
    StoreVectors -->|ChromaDB| SaveChroma[ChromaDB保存<br/>・自動永続化]
    StoreVectors -->|FAISS| SaveFAISS[FAISS保存<br/>・手動永続化]
    
    SaveChroma --> BuildMetaIndex
    SaveFAISS --> BuildMetaIndex
    
    BuildMetaIndex[メタデータインデックス構築<br/>・API関数インデックス<br/>・ドキュメントタイプ<br/>・セクション情報]
    
    BuildMetaIndex --> SaveCache[キャッシュ保存<br/>・統計情報<br/>・インデックス作成時刻]
    
    SaveCache --> BuildEnd([構築完了])
    
    style BuildStart fill:#e1f5fe
    style TextProcessing fill:#fff3e0
    style CreateVectors fill:#f3e5f5
    style BuildEnd fill:#c8e6c9
```

### 3. RAG検索フェーズ

```mermaid
graph TB
    SearchStart([検索開始]) --> CheckSearchType{検索タイプ?}
    
    CheckSearchType -->|シンク解析| SinkAnalysis[search_for_sink_analysis]
    CheckSearchType -->|脆弱性解析| VulnAnalysis[search_for_vulnerability_analysis]
    
    %% シンク解析フロー
    SinkAnalysis --> CreateQueries1[検索クエリ生成<br/>・&quot;api_name&quot; function<br/>・api_name parameters<br/>・api_name description]
    
    CreateQueries1 --> RetrieveSink[retrieve_for_sink_identification]
    RetrieveSink --> SearchByAPI[API優先検索<br/>・search_by_api呼び出し<br/>・メタデータフィルタ]
    
    SearchByAPI --> SecurityKeywords[セキュリティキーワード検索<br/>・security<br/>・vulnerability<br/>・buffer overflow<br/>・validation]
    
    SecurityKeywords --> ScoreDocs1[文書スコアリング<br/>・API定義: +0.5<br/>・セキュリティキーワード: +0.05<br/>・パラメータ記述: +0.1]
    
    ScoreDocs1 --> SortDocs1[スコア降順ソート]
    SortDocs1 --> FilterRegex1[正規表現フィルタ<br/>・api_name完全一致のみ]
    
    FilterRegex1 --> BuildContext1[コンテキスト構築（最大3000文字）]
    BuildContext1 --> APIDef{API定義<br/>あり?}
    
    APIDef -->|Yes| AddAPISection[API定義セクション追加]
    APIDef -->|No| SecuritySection
    
    AddAPISection --> SecuritySection[セキュリティセクション追加]
    SecuritySection --> FormatContext1[コンテキスト整形<br/>・ソース情報付与<br/>・ページ番号付与]
    
    %% 脆弱性解析フロー
    VulnAnalysis --> ExtractFunctions[関数呼び出し抽出<br/>・コードスニペット解析<br/>・TEE関連関数のみ]
    
    ExtractFunctions --> CreateQueries2[複合クエリ生成]
    CreateQueries2 --> Query1[シンク詳細検索<br/>・search_by_api]
    CreateQueries2 --> Query2[パラメータ検証検索<br/>・param validation]
    CreateQueries2 --> Query3[脆弱性パターン検索<br/>・buffer overflow<br/>・integer overflow<br/>・null pointer]
    
    Query1 --> CollectResults
    Query2 --> CollectResults
    Query3 --> CollectResults
    
    CollectResults[結果収集]
    CollectResults --> ScoreDocs2[文書スコアリング<br/>・シンク言及: +0.3<br/>・呼び出し関数: +0.1<br/>・脆弱性キーワード: +0.05<br/>・CWE参照: +0.2]
    
    ScoreDocs2 --> Dedup[重複除去<br/>・ファイル名/ページ番号]
    
    Dedup --> WindowExtract[ウィンドウ抽出<br/>・シンク周辺±500文字]
    
    WindowExtract --> BuildContext2[コンテキスト構築（最大3000文字）]
    BuildContext2 --> SinkInfo{シンク情報<br/>あり?}
    
    SinkInfo -->|Yes| AddSinkSection[シンク情報セクション]
    SinkInfo -->|No| ParamSection
    
    AddSinkSection --> ParamSection[パラメータ検証セクション]
    ParamSection --> VulnPatternSection[脆弱性パターンセクション]
    
    VulnPatternSection --> FormatContext2[コンテキスト整形]
    
    FormatContext1 --> ReturnContext[コンテキスト返却]
    FormatContext2 --> ReturnContext
    
    ReturnContext --> SearchEnd([検索完了])
    
    style SearchStart fill:#e1f5fe
    style SinkAnalysis fill:#fff3e0
    style VulnAnalysis fill:#f3e5f5
    style SearchEnd fill:#c8e6c9
```

### 4. LLM問い合わせフェーズ

```mermaid
graph TB
    LLMStart([LLM処理開始]) --> InitClient[UnifiedLLMClient初期化]
    
    InitClient --> LoadConfig[ConfigManager初期化<br/>・llm_config.json読み込み<br/>・プロバイダー設定確認]
    
    LoadConfig --> CheckProvider{アクティブ<br/>プロバイダー?}
    
    CheckProvider -->|OpenAI| InitOpenAI[OpenAIClient生成]
    CheckProvider -->|Claude| InitClaude[ClaudeClient生成]
    CheckProvider -->|DeepSeek| InitDeepSeek[DeepSeekClient生成]
    CheckProvider -->|Gemini| InitGemini[GeminiClient生成]
    CheckProvider -->|Ollama| InitOllama[LocalLLMClient生成]
    
    InitOpenAI --> BuildPrompt
    InitClaude --> BuildPrompt
    InitDeepSeek --> BuildPrompt
    InitGemini --> BuildPrompt
    InitOllama --> BuildPrompt
    
    BuildPrompt[プロンプト構築]
    BuildPrompt --> SystemPrompt[システムプロンプト]
    BuildPrompt --> RAGContext[RAGコンテキスト挿入]
    BuildPrompt --> UserQuery[ユーザークエリ/コード]
    
    SystemPrompt --> CreateMessages
    RAGContext --> CreateMessages
    UserQuery --> CreateMessages
    
    CreateMessages[メッセージ配列作成<br/>role: system/user/assistant]
    
    CreateMessages --> InitRetry[LLMRetryHandler初期化<br/>・最大リトライ: 3<br/>・基本遅延: 2秒]
    
    InitRetry --> RateLimiter[レート制限待機<br/>・最小間隔: 0.7秒]
    
    RateLimiter --> CallLLM[LLM API呼び出し]
    
    CallLLM --> CheckResponse{レスポンス<br/>検証}
    
    CheckResponse -->|成功| ValidResponse[有効レスポンス]
    CheckResponse -->|空/None| DiagnoseEmpty
    CheckResponse -->|エラー| AnalyzeError
    
    ValidResponse --> ReturnResponse[レスポンス返却]
    
    DiagnoseEmpty[空レスポンス診断]
    DiagnoseEmpty --> ResponseAnalysis[レスポンス分析<br/>・型チェック<br/>・長さ確認<br/>・16進ダンプ]
    DiagnoseEmpty --> PromptAnalysis[プロンプト分析<br/>・文字数<br/>・トークン推定<br/>・特殊文字]
    DiagnoseEmpty --> EnvAnalysis[環境分析<br/>・APIキー確認<br/>・プロバイダー設定<br/>・メモリ使用量]
    DiagnoseEmpty --> APITest[API接続テスト<br/>・簡単なプロンプト送信<br/>・応答時間測定]
    
    ResponseAnalysis --> GenerateDiagnosis
    PromptAnalysis --> GenerateDiagnosis
    EnvAnalysis --> GenerateDiagnosis
    APITest --> GenerateDiagnosis
    
    GenerateDiagnosis[診断レポート生成<br/>・原因リスト<br/>・推奨事項]
    
    AnalyzeError[エラー分析]
    AnalyzeError --> CheckErrorType{エラータイプ?}
    
    CheckErrorType -->|TIMEOUT| TimeoutError[タイムアウト処理]
    CheckErrorType -->|RATE_LIMIT| RateError[レート制限処理]
    CheckErrorType -->|TOKEN_LIMIT| TokenError[トークン制限処理]
    CheckErrorType -->|AUTH_ERROR| AuthError[認証エラー処理]
    CheckErrorType -->|CONTENT_FILTER| ContentError[コンテンツフィルタ処理]
    CheckErrorType -->|その他| UnknownError[不明エラー処理]
    
    GenerateDiagnosis --> CheckRetry
    TimeoutError --> CheckRetry
    RateError --> CheckRetry
    TokenError --> NoRetry
    AuthError --> NoRetry
    ContentError --> NoRetry
    UnknownError --> CheckRetry
    
    CheckRetry{リトライ<br/>判定}
    CheckRetry -->|可能| CalculateDelay[遅延計算<br/>・指数バックオフ<br/>・最大60秒]
    CheckRetry -->|不可| NoRetry
    
    NoRetry[リトライ中止]
    
    CalculateDelay --> WaitDelay[遅延待機]
    WaitDelay --> IncrementAttempt[試行回数+1]
    
    IncrementAttempt --> CheckMaxRetry{最大試行<br/>到達?}
    CheckMaxRetry -->|No| RateLimiter
    CheckMaxRetry -->|Yes| FatalError
    
    NoRetry --> FatalError[致命的エラー処理]
    
    FatalError --> LogError[エラーログ記録<br/>・詳細ログ<br/>・JSON形式<br/>・診断レポート]
    
    LogError --> DisplayError[エラー表示<br/>・エラー履歴<br/>・診断ファイル情報]
    
    DisplayError --> Exit([プログラム終了])
    ReturnResponse --> LLMEnd([LLM処理完了])
    
    style LLMStart fill:#e1f5fe
    style BuildPrompt fill:#fff3e0
    style CallLLM fill:#f3e5f5
    style DiagnoseEmpty fill:#fce4ec
    style FatalError fill:#ffcdd2
    style LLMEnd fill:#c8e6c9
```

### 5. プロバイダー別処理詳細

```mermaid
graph TB
    Provider[プロバイダー処理] --> CheckType{プロバイダー<br/>タイプ?}
    
    CheckType -->|OpenAI系| OpenAIFlow[OpenAI互換処理]
    CheckType -->|Claude| ClaudeFlow[Claude処理]
    CheckType -->|Gemini| GeminiFlow[Gemini処理]
    CheckType -->|Local| LocalFlow[ローカル処理]
    
    %% OpenAI系処理
    OpenAIFlow --> OpenAIClient[OpenAI Client使用]
    OpenAIClient --> CreateCompletion[chat.completions.create&#40;&#41;]
    CreateCompletion --> OpenAIParams[パラメータ設定<br/>・model<br/>・temperature: 0.0<br/>・max_tokens: 4096<br/>・timeout: 60]
    
    %% Claude処理
    ClaudeFlow --> ClaudeClient[Anthropic Client使用]
    ClaudeClient --> ConvertMessages[メッセージ変換<br/>・systemをuserに統合]
    ConvertMessages --> CreateMessage[messages.create&#40;&#41;]
    CreateMessage --> ClaudeParams[パラメータ設定<br/>・model<br/>・temperature: 0.0<br/>・max_tokens: 4096]
    
    %% Gemini処理
    GeminiFlow --> GeminiClient[GenerativeModel使用]
    GeminiClient --> StartChat[start_chat&#40;&#41;初期化]
    StartChat --> MergeSystem[システムメッセージ統合<br/>・最初のuserに結合]
    MergeSystem --> SendMessage[send_message&#40;&#41;]
    SendMessage --> GeminiParams[パラメータ設定<br/>・temperature: 0.0<br/>・max_output_tokens: 8192<br/>・safety_settings]
    
    %% ローカル処理
    LocalFlow --> LocalClient[REST API直接呼び出し]
    LocalClient --> PreparePayload[ペイロード準備<br/>・model<br/>・messages<br/>・stream: false]
    PreparePayload --> PostRequest[POST /api/chat]
    PostRequest --> LocalParams[パラメータ設定<br/>・temperature: 0.0<br/>・num_predict: 4096<br/>・timeout: 120]
    
    OpenAIParams --> ExtractContent
    ClaudeParams --> ExtractContent
    GeminiParams --> ExtractContent
    LocalParams --> ExtractContent
    
    ExtractContent[コンテンツ抽出]
    ExtractContent --> ReturnText[テキスト返却]
    
    style Provider fill:#e1f5fe
    style ExtractContent fill:#c8e6c9
```

### 6. エラー処理とリカバリフロー

```mermaid
graph TB
    ErrorOccur([エラー発生]) --> ErrorAnalyzer[LLMErrorAnalyzer]
    
    ErrorAnalyzer --> CheckException{例外タイプ?}
    
    CheckException -->|HTTPエラー| HTTPAnalysis[HTTP分析<br/>・ステータスコード<br/>・レスポンステキスト]
    CheckException -->|その他| PatternMatch[パターンマッチング]
    
    HTTPAnalysis --> StatusMap{ステータス<br/>コード?}
    
    StatusMap -->|429| CreateRateLimit[RATE_LIMIT生成]
    StatusMap -->|408/504| CreateTimeout[TIMEOUT生成]
    StatusMap -->|401| CreateAuth[AUTH_ERROR生成]
    StatusMap -->|400| Check400{内容確認}
    StatusMap -->|500-503| CreateServer[SERVER_ERROR生成]
    
    Check400 -->|content_filter| CreateFilter[CONTENT_FILTER生成]
    Check400 -->|その他| CreateBadRequest[BAD_REQUEST生成]
    
    PatternMatch --> MatchPatterns{パターン<br/>一致?}
    
    MatchPatterns -->|timeout| CreateTimeout2[TIMEOUT生成]
    MatchPatterns -->|rate/limit| CreateRateLimit2[RATE_LIMIT生成]
    MatchPatterns -->|token/context| CreateTokenLimit[TOKEN_LIMIT生成]
    MatchPatterns -->|filter/blocked| CreateFilter2[CONTENT_FILTER生成]
    MatchPatterns -->|connection| CreateNetwork[NETWORK_ERROR生成]
    MatchPatterns -->|unauthorized| CreateAuth2[AUTH_ERROR生成]
    MatchPatterns -->|なし| CreateUnknown[UNKNOWN_ERROR生成]
    
    CreateRateLimit --> LLMError
    CreateTimeout --> LLMError
    CreateAuth --> LLMError
    CreateFilter --> LLMError
    CreateBadRequest --> LLMError
    CreateServer --> LLMError
    CreateTimeout2 --> LLMError
    CreateRateLimit2 --> LLMError
    CreateTokenLimit --> LLMError
    CreateFilter2 --> LLMError
    CreateNetwork --> LLMError
    CreateAuth2 --> LLMError
    CreateUnknown --> LLMError
    
    LLMError[LLMErrorオブジェクト<br/>・error_type<br/>・message<br/>・details<br/>・timestamp]
    
    LLMError --> ErrorLogger[LLMErrorLogger]
    
    ErrorLogger --> LogDetail[詳細ログ記録<br/>llm_error_details.log]
    ErrorLogger --> LogJSON[JSON記録<br/>llm_errors.json]
    ErrorLogger --> LogDiagnosis[診断記録<br/>llm_diagnosis_report.json]
    
    LogDetail --> RetryDecision
    LogJSON --> RetryDecision
    LogDiagnosis --> RetryDecision
    
    RetryDecision{リトライ<br/>戦略?}
    
    RetryDecision -->|NO_RETRY| StopTypes{エラータイプ?}
    StopTypes -->|AUTH_ERROR| NoRetryAuth[認証エラー<br/>リトライ不可]
    StopTypes -->|TOKEN_LIMIT| NoRetryToken[トークン制限<br/>リトライ不可]
    StopTypes -->|CONTENT_FILTER| NoRetryContent[コンテンツ<br/>リトライ不可]
    
    RetryDecision -->|RETRY| RetryTypes{エラータイプ?}
    RetryTypes -->|TIMEOUT| TimeoutStrategy[タイムアウト戦略<br/>・最大2回]
    RetryTypes -->|RATE_LIMIT| RateStrategy[レート制限戦略<br/>・指数バックオフ<br/>・最大60秒]
    RetryTypes -->|SERVER_ERROR| ServerStrategy[サーバーエラー戦略<br/>・長め遅延<br/>・最大30秒]
    RetryTypes -->|その他| DefaultStrategy[デフォルト戦略<br/>・基本遅延2秒]
    
    NoRetryAuth --> Fatal
    NoRetryToken --> Fatal
    NoRetryContent --> Fatal
    
    TimeoutStrategy --> ExecuteRetry
    RateStrategy --> ExecuteRetry
    ServerStrategy --> ExecuteRetry
    DefaultStrategy --> ExecuteRetry
    
    ExecuteRetry[リトライ実行]
    ExecuteRetry --> Success{成功?}
    
    Success -->|Yes| RecoverSuccess[正常復帰]
    Success -->|No| CheckAttempts{試行回数<br/>チェック}
    
    CheckAttempts -->|残りあり| ExecuteRetry
    CheckAttempts -->|上限到達| Fatal
    
    Fatal[致命的エラー]
    Fatal --> FatalLog[致命的エラーログ<br/>llm_fatal_error.log<br/>llm_fatal_diagnosis.json]
    
    FatalLog --> DisplaySummary[サマリー表示<br/>・エラー履歴<br/>・診断ファイル一覧]
    
    DisplaySummary --> SystemExit[sys.exit&#40;1&#41;]
    RecoverSuccess --> Continue[処理継続]
    
    style ErrorOccur fill:#ffcdd2
    style LLMError fill:#fff3e0
    style Fatal fill:#ef5350
    style RecoverSuccess fill:#c8e6c9
```
