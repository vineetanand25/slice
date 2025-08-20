/**
 * @name Interprocedural Use-After-Free Detection
 * @description Detects UAF bugs with type-aware flow tracking
 * @kind problem
 * @id cpp/interprocedural-uaf
 * @tags security
 */

import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import semmle.code.cpp.dataflow.new.TaintTracking

//-----------------------------------------------------------------------------
// CORE DEFINITIONS
//-----------------------------------------------------------------------------

/** 
 * Memory deallocation functions
 * Examples: free(), kfree(), delete, custom_free_buffer(), my_free_function()
 */
class FreeFunction extends Function {
  FreeFunction() {
    this.getName().matches("%free%") or  // Matches: free, kfree, custom_free_*, myfree, free_buffer
    this.getName() = "delete" or         // Matches: C++ delete operator
    this.getName() = "operator delete"   // Matches: C++ operator delete
  }
}

/** 
 * Function calls to free functions
 * Example: free(ptr); kfree(buffer); delete obj;
 */
class FreeCall extends FunctionCall {
  FreeCall() { this.getTarget() instanceof FreeFunction }
}

//-----------------------------------------------------------------------------
// TYPE CHECKING
//-----------------------------------------------------------------------------

/** Check if two types are compatible for UAF tracking */
predicate typesCompatible(Type t1, Type t2) {
  // Exact same type
  // Example: both are "struct buffer*"
  t1 = t2
  or
  // Both are pointers to compatible types
  exists(PointerType pt1, PointerType pt2 |
    pt1 = t1 and pt2 = t2 and
    (
      // Same base type - Example: both are "int*"
      pt1.getBaseType() = pt2.getBaseType() or
      // void* is compatible with any pointer - Example: void* and char*
      pt1.getBaseType() instanceof VoidType or
      pt2.getBaseType() instanceof VoidType
    )
  )
  or
  // Handle typedefs
  // Example: typedef struct buffer buffer_t; then buffer_t* and struct buffer* are compatible
  exists(TypedefType td | 
    td = t1 and typesCompatible(td.getBaseType(), t2)
    or
    td = t2 and typesCompatible(t1, td.getBaseType())
  )
}

//-----------------------------------------------------------------------------
// CALL GRAPH ANALYSIS - USING BUILT-IN
//-----------------------------------------------------------------------------

/** 
 * Check if two functions are related through calls
 * Example: func1() calls func2(), or both are called by main()
 */
predicate functionsRelated(Function f1, Function f2) {
  // Can reach each other through any number of calls
  // Example: f1 -> intermediate1 -> intermediate2 -> f2
  f1.calls*(f2) or f2.calls*(f1)
  or
  // Share a common caller (siblings in call graph)
  // Example: main() calls both f1() and f2()
  exists(Function parent | 
    parent.calls+(f1) and parent.calls+(f2)
  )
}

//-----------------------------------------------------------------------------
// DATAFLOW CONFIGURATION
//-----------------------------------------------------------------------------

module UAFConfig implements DataFlow::ConfigSig {
  /** 
   * Sources are arguments to free calls
   * Example: in "free(ptr)", ptr is the source
   */
  predicate isSource(DataFlow::Node source) {
    exists(FreeCall fc | fc.getAnArgument() = source.asExpr())
  }
  
  /** 
   * Sinks are dangerous uses of freed pointers
   */
  predicate isSink(DataFlow::Node sink) {
    exists(Expr e | e = sink.asExpr() |
      // Dereference - Example: *ptr
      e.getParent() instanceof PointerDereferenceExpr or
      // Array access - Example: ptr[5]
      e.getParent() instanceof ArrayExpr or
      // Field access - Example: ptr->field or ptr->flags
      exists(PointerFieldAccess pfa | pfa.getQualifier() = e)
    )
  }
  
  predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {
    // Flow through struct field assignments
    // Example: obj->data = freed_ptr; (freed_ptr flows to obj)
    exists(AssignExpr assign, PointerFieldAccess pfa |
      assign.getRValue() = node1.asExpr() and
      assign.getLValue() = pfa and
      node2.asExpr() = pfa.getQualifier() and
      typesCompatible(node1.asExpr().getType(), pfa.getType())
    )
    or
    // Flow from struct to field access
    // Example: ctx->data (ctx flows to ctx->data)
    exists(PointerFieldAccess pfa |
      pfa.getQualifier() = node1.asExpr() and
      pfa = node2.asExpr()
    )
    or
    // Flow through function parameters (forward)
    // Example: func(ptr) - ptr flows to the parameter
    exists(FunctionCall call, Function f, Parameter p, int i |
      call.getArgument(i) = node1.asExpr() and
      f = call.getTarget() and
      p = f.getParameter(i) and
      node2.asParameter() = p and
      typesCompatible(node1.asExpr().getType(), p.getType())
    )
    or
    // Flow through function parameters (backward)
    // Example: parameter flows back to call site
    exists(FunctionCall call, Function f, Parameter p, int i |
      f = call.getTarget() and
      p = f.getParameter(i) and
      node1.asParameter() = p and
      node2.asExpr() = call.getArgument(i) and
      typesCompatible(p.getType(), call.getArgument(i).getType())
    )
    or
    // Flow through local assignments
    // Example: new_ptr = old_ptr;
    exists(AssignExpr assign |
      assign.getRValue() = node1.asExpr() and
      assign.getLValue() = node2.asExpr() and
      typesCompatible(node1.asExpr().getType(), node2.asExpr().getType())
    )
    or
    // Flow through returns
    // Example: return ptr; (ptr flows to the call site)
    exists(ReturnStmt ret, FunctionCall call |
      ret.getExpr() = node1.asExpr() and
      ret.getEnclosingFunction() = call.getTarget() and
      node2.asExpr() = call and
      typesCompatible(node1.asExpr().getType(), call.getType())
    )
    or
    // Track same variable across related functions
    // Example: global_ptr accessed in both func1() and func2()
    exists(Variable v, Function f1, Function f2 |
      node1.asExpr() = v.getAnAccess() and
      node2.asExpr() = v.getAnAccess() and
      f1 = node1.asExpr().getEnclosingFunction() and
      f2 = node2.asExpr().getEnclosingFunction() and
      f1 != f2 and
      functionsRelated(f1, f2) and
      typesCompatible(node1.asExpr().getType(), node2.asExpr().getType())
    )
  }
  
  predicate isBarrier(DataFlow::Node node) {
    // NULL assignment (sanitization)
    // Example: ptr = NULL;
    exists(AssignExpr assign |
      assign.getLValue() = node.asExpr() and
      assign.getRValue().getValue() = "0"
    )
    or
    // Reallocation
    // Example: ptr = malloc(size); ptr = kmalloc(size, GFP_KERNEL);
    exists(AssignExpr assign, FunctionCall alloc |
      assign.getLValue() = node.asExpr() and
      assign.getRValue() = alloc and
      alloc.getTarget().getName() in ["malloc", "calloc", "realloc", 
                                      "kmalloc", "kzalloc", "new", "operator new"]
    )
  }
}

module UAFFlow = TaintTracking::Global<UAFConfig>;

//-----------------------------------------------------------------------------
// HELPER FUNCTIONS
//-----------------------------------------------------------------------------

/** 
 * Get the type of the freed pointer
 * Example: for free(ptr) where ptr is "struct buffer*", returns "struct buffer*"
 */
Type getFreedType(DataFlow::Node freeSource) {
  exists(FreeCall fc |
    fc.getAnArgument() = freeSource.asExpr() and
    result = freeSource.asExpr().getType()
  )
}

/** 
 * Get a readable name for an expression
 * Examples: "ctx->data", "buffer", "ptr"
 */
string getObjectName(Expr e) {
  // Variable name - Example: "ptr"
  exists(Variable v | v.getAnAccess() = e | result = v.getName())
  or
  // Field access - Example: "ctx->data"
  exists(PointerFieldAccess pfa | pfa = e | result = pfa.toString())
  or
  // Fallback to string representation
  result = e.toString()
}

//-----------------------------------------------------------------------------
// MAIN QUERY
//-----------------------------------------------------------------------------

from DataFlow::Node freeSource, DataFlow::Node usePoint,
     Function freeFunc, Function useFunc, FreeCall fc,
     string objName, string ffName, string ffFile, int ffDefLine, int freeLine,
     string fuName, string fuFile, int fuDefLine, int useLine
where
  // Track flow from freed expressions to dangerous uses
  UAFFlow::flow(freeSource, usePoint) and
  
  // Get the free call details
  fc.getAnArgument() = freeSource.asExpr() and
  freeFunc = fc.getEnclosingFunction() and
  useFunc = usePoint.asExpr().getEnclosingFunction() and
  
  // Ensure interprocedural (free and use in different functions)
  freeFunc != useFunc and
  
  // Type compatibility check
  typesCompatible(getFreedType(freeSource), usePoint.asExpr().getType()) and
  
  // Extract all fields for CSV output
  objName = getObjectName(freeSource.asExpr()) and
  ffName = freeFunc.getName() and
  ffFile = freeFunc.getFile().getRelativePath() and
  ffDefLine = freeFunc.getLocation().getStartLine() and
  freeLine = fc.getLocation().getStartLine() and
  fuName = useFunc.getName() and
  fuFile = useFunc.getFile().getRelativePath() and
  fuDefLine = useFunc.getLocation().getStartLine() and
  useLine = usePoint.getLocation().getStartLine()

// CSV format output
select usePoint,
       objName as object,           // object
       ffName as free_func,         // free_func
       ffFile as free_file,         // free_file
       ffDefLine as free_func_def_ln, // free_func_def_ln
       freeLine as free_ln,         // free_ln
       fuName as use_func,          // use_func
       fuFile as use_file,          // use_file
       fuDefLine as use_func_def_ln,   // use_func_def_ln
       useLine as use_ln            // use_ln
