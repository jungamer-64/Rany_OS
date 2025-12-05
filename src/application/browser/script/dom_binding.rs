// ============================================================================
// src/application/browser/script/dom_binding.rs - DOM Bindings
// ============================================================================
//!
//! # DOMバインディング
//!
//! RustScriptからDOMを操作するためのインターフェース。

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;
use alloc::vec;

use super::value::{ScriptValue, ElementRef, NativeFunction, NativeFunctionId};
use super::vm::DomOperation;

// ============================================================================
// DOM Binding
// ============================================================================

/// DOMバインディング
pub struct DomBinding {
    /// 要素キャッシュ（ID -> ElementRef）
    element_cache: BTreeMap<usize, ElementInfo>,
    /// HTML ID から内部IDへのマップ
    id_to_element: BTreeMap<String, usize>,
    /// クラスから要素IDリストへのマップ
    class_to_elements: BTreeMap<String, Vec<usize>>,
    /// タグ名から要素IDリストへのマップ
    tag_to_elements: BTreeMap<String, Vec<usize>>,
    /// 次の要素ID
    next_element_id: usize,
    /// イベントハンドラ
    event_handlers: BTreeMap<(usize, String), Vec<usize>>,
}

/// 要素情報
#[derive(Debug, Clone)]
struct ElementInfo {
    /// 要素ID
    id: usize,
    /// タグ名
    tag_name: String,
    /// HTML id属性
    html_id: Option<String>,
    /// クラス名リスト
    classes: Vec<String>,
    /// 属性
    attributes: BTreeMap<String, String>,
    /// テキストコンテンツ
    text_content: String,
    /// スタイル
    styles: BTreeMap<String, String>,
    /// 親要素ID
    parent_id: Option<usize>,
    /// 子要素IDリスト
    children: Vec<usize>,
}

impl DomBinding {
    pub fn new() -> Self {
        Self {
            element_cache: BTreeMap::new(),
            id_to_element: BTreeMap::new(),
            class_to_elements: BTreeMap::new(),
            tag_to_elements: BTreeMap::new(),
            next_element_id: 1,
            event_handlers: BTreeMap::new(),
        }
    }

    /// 初期DOM構造を設定（HTMLパーサーから呼ばれる）
    pub fn initialize_from_html(&mut self, root: &DocumentNode) {
        self.build_element_tree(root, None);
    }

    /// 要素ツリーを構築
    fn build_element_tree(&mut self, node: &DocumentNode, parent_id: Option<usize>) {
        let id = self.next_element_id;
        self.next_element_id += 1;

        let info = ElementInfo {
            id,
            tag_name: node.tag_name.clone(),
            html_id: node.id.clone(),
            classes: node.classes.clone(),
            attributes: node.attributes.clone(),
            text_content: node.text_content.clone(),
            styles: BTreeMap::new(),
            parent_id,
            children: Vec::new(),
        };

        // インデックスを更新
        if let Some(ref html_id) = node.id {
            self.id_to_element.insert(html_id.clone(), id);
        }

        for class in &node.classes {
            self.class_to_elements
                .entry(class.clone())
                .or_insert_with(Vec::new)
                .push(id);
        }

        self.tag_to_elements
            .entry(node.tag_name.clone())
            .or_insert_with(Vec::new)
            .push(id);

        self.element_cache.insert(id, info);

        // 子要素を処理
        let mut child_ids = Vec::new();
        for child in &node.children {
            self.build_element_tree(child, Some(id));
            child_ids.push(self.next_element_id - 1);
        }

        // 子要素IDを更新
        if let Some(info) = self.element_cache.get_mut(&id) {
            info.children = child_ids;
        }
    }

    /// DOM操作を処理
    pub fn handle_operation(&mut self, op: DomOperation) -> ScriptValue {
        match op {
            DomOperation::GetElementById(id) => {
                if let Some(&elem_id) = self.id_to_element.get(&id) {
                    self.create_element_ref(elem_id)
                } else {
                    ScriptValue::Nil
                }
            }
            DomOperation::GetElementsByClass(class) => {
                if let Some(ids) = self.class_to_elements.get(&class) {
                    let elements: Vec<ScriptValue> = ids.iter()
                        .map(|&id| self.create_element_ref(id))
                        .collect();
                    ScriptValue::Array(elements)
                } else {
                    ScriptValue::Array(Vec::new())
                }
            }
            DomOperation::GetElementsByTag(tag) => {
                if let Some(ids) = self.tag_to_elements.get(&tag) {
                    let elements: Vec<ScriptValue> = ids.iter()
                        .map(|&id| self.create_element_ref(id))
                        .collect();
                    ScriptValue::Array(elements)
                } else {
                    ScriptValue::Array(Vec::new())
                }
            }
            DomOperation::CreateElement(tag) => {
                let id = self.next_element_id;
                self.next_element_id += 1;

                let info = ElementInfo {
                    id,
                    tag_name: tag.clone(),
                    html_id: None,
                    classes: Vec::new(),
                    attributes: BTreeMap::new(),
                    text_content: String::new(),
                    styles: BTreeMap::new(),
                    parent_id: None,
                    children: Vec::new(),
                };

                self.tag_to_elements
                    .entry(tag)
                    .or_insert_with(Vec::new)
                    .push(id);

                self.element_cache.insert(id, info);

                self.create_element_ref(id)
            }
            DomOperation::AppendChild(parent_id, child_id) => {
                // 子要素の親を更新
                if let Some(child) = self.element_cache.get_mut(&child_id) {
                    // 既存の親から削除
                    if let Some(old_parent_id) = child.parent_id {
                        if let Some(old_parent) = self.element_cache.get_mut(&old_parent_id) {
                            old_parent.children.retain(|&id| id != child_id);
                        }
                    }
                    child.parent_id = Some(parent_id);
                }

                // 親要素の子リストに追加
                if let Some(parent) = self.element_cache.get_mut(&parent_id) {
                    if !parent.children.contains(&child_id) {
                        parent.children.push(child_id);
                    }
                }

                ScriptValue::Bool(true)
            }
            DomOperation::RemoveChild(parent_id, child_id) => {
                if let Some(parent) = self.element_cache.get_mut(&parent_id) {
                    parent.children.retain(|&id| id != child_id);
                }
                if let Some(child) = self.element_cache.get_mut(&child_id) {
                    child.parent_id = None;
                }
                ScriptValue::Bool(true)
            }
            DomOperation::SetAttribute(id, name, value) => {
                if let Some(elem) = self.element_cache.get_mut(&id) {
                    // 特殊属性の処理
                    match name.as_str() {
                        "id" => {
                            // 古いIDを削除
                            if let Some(ref old_id) = elem.html_id {
                                self.id_to_element.remove(old_id);
                            }
                            // 新しいIDを登録
                            self.id_to_element.insert(value.clone(), id);
                            elem.html_id = Some(value);
                        }
                        "class" => {
                            // 古いクラスを削除
                            for class in &elem.classes {
                                if let Some(ids) = self.class_to_elements.get_mut(class) {
                                    ids.retain(|&eid| eid != id);
                                }
                            }
                            // 新しいクラスを設定
                            let classes: Vec<String> = value.split_whitespace()
                                .map(String::from)
                                .collect();
                            for class in &classes {
                                self.class_to_elements
                                    .entry(class.clone())
                                    .or_insert_with(Vec::new)
                                    .push(id);
                            }
                            elem.classes = classes;
                        }
                        _ => {
                            elem.attributes.insert(name, value);
                        }
                    }
                    ScriptValue::Bool(true)
                } else {
                    ScriptValue::Bool(false)
                }
            }
            DomOperation::GetAttribute(id, name) => {
                if let Some(elem) = self.element_cache.get(&id) {
                    match name.as_str() {
                        "id" => elem.html_id.clone()
                            .map(ScriptValue::String)
                            .unwrap_or(ScriptValue::Nil),
                        "class" => ScriptValue::String(elem.classes.join(" ")),
                        _ => elem.attributes.get(&name)
                            .cloned()
                            .map(ScriptValue::String)
                            .unwrap_or(ScriptValue::Nil),
                    }
                } else {
                    ScriptValue::Nil
                }
            }
            DomOperation::SetText(id, text) => {
                if let Some(elem) = self.element_cache.get_mut(&id) {
                    elem.text_content = text;
                    ScriptValue::Bool(true)
                } else {
                    ScriptValue::Bool(false)
                }
            }
            DomOperation::GetText(id) => {
                if let Some(elem) = self.element_cache.get(&id) {
                    ScriptValue::String(elem.text_content.clone())
                } else {
                    ScriptValue::Nil
                }
            }
            DomOperation::SetStyle(id, property, value) => {
                if let Some(elem) = self.element_cache.get_mut(&id) {
                    elem.styles.insert(property, value);
                    ScriptValue::Bool(true)
                } else {
                    ScriptValue::Bool(false)
                }
            }
            DomOperation::GetStyle(id, property) => {
                if let Some(elem) = self.element_cache.get(&id) {
                    elem.styles.get(&property)
                        .cloned()
                        .map(ScriptValue::String)
                        .unwrap_or(ScriptValue::Nil)
                } else {
                    ScriptValue::Nil
                }
            }
            DomOperation::AddClass(id, class) => {
                if let Some(elem) = self.element_cache.get_mut(&id) {
                    if !elem.classes.contains(&class) {
                        elem.classes.push(class.clone());
                        self.class_to_elements
                            .entry(class)
                            .or_insert_with(Vec::new)
                            .push(id);
                    }
                    ScriptValue::Bool(true)
                } else {
                    ScriptValue::Bool(false)
                }
            }
            DomOperation::RemoveClass(id, class) => {
                if let Some(elem) = self.element_cache.get_mut(&id) {
                    elem.classes.retain(|c| c != &class);
                    if let Some(ids) = self.class_to_elements.get_mut(&class) {
                        ids.retain(|&eid| eid != id);
                    }
                    ScriptValue::Bool(true)
                } else {
                    ScriptValue::Bool(false)
                }
            }
            DomOperation::AddEventListener(elem_id, event, handler_addr) => {
                let key = (elem_id, event);
                self.event_handlers
                    .entry(key)
                    .or_insert_with(Vec::new)
                    .push(handler_addr);
                ScriptValue::Bool(true)
            }
        }
    }

    /// ElementRefを作成
    fn create_element_ref(&self, id: usize) -> ScriptValue {
        if let Some(elem) = self.element_cache.get(&id) {
            let mut elem_ref = ElementRef::new(id, &elem.tag_name);
            if let Some(ref html_id) = elem.html_id {
                elem_ref = elem_ref.with_html_id(html_id);
            }
            elem_ref = elem_ref.with_classes(elem.classes.clone());
            ScriptValue::Element(elem_ref)
        } else {
            ScriptValue::Nil
        }
    }

    /// 要素のイベントを発火
    pub fn dispatch_event(&self, elem_id: usize, event_type: &str) -> Vec<usize> {
        let key = (elem_id, String::from(event_type));
        self.event_handlers.get(&key)
            .cloned()
            .unwrap_or_default()
    }

    /// グローバルオブジェクト「document」を生成
    pub fn create_document_object(&self) -> ScriptValue {
        let mut doc = BTreeMap::new();

        // document.bodyへの参照
        if let Some(&body_id) = self.tag_to_elements.get("body").and_then(|ids| ids.first()) {
            doc.insert(String::from("body"), self.create_element_ref(body_id));
        }

        // document.headへの参照
        if let Some(&head_id) = self.tag_to_elements.get("head").and_then(|ids| ids.first()) {
            doc.insert(String::from("head"), self.create_element_ref(head_id));
        }

        ScriptValue::Object(doc)
    }

    /// ネイティブDOM関数を登録
    pub fn register_native_functions() -> Vec<(String, NativeFunction)> {
        vec![
            (String::from("getElementById"), NativeFunction::new("getElementById", NativeFunctionId::DomGetElementById, 1)),
            (String::from("getElementsByClass"), NativeFunction::new("getElementsByClass", NativeFunctionId::DomGetElementsByClass, 1)),
            (String::from("getElementsByTag"), NativeFunction::new("getElementsByTag", NativeFunctionId::DomGetElementsByTag, 1)),
            (String::from("createElement"), NativeFunction::new("createElement", NativeFunctionId::DomCreateElement, 1)),
            (String::from("appendChild"), NativeFunction::new("appendChild", NativeFunctionId::DomAppendChild, 2)),
            (String::from("removeChild"), NativeFunction::new("removeChild", NativeFunctionId::DomRemoveChild, 2)),
            (String::from("setAttribute"), NativeFunction::new("setAttribute", NativeFunctionId::DomSetAttribute, 3)),
            (String::from("getAttribute"), NativeFunction::new("getAttribute", NativeFunctionId::DomGetAttribute, 2)),
            (String::from("setText"), NativeFunction::new("setText", NativeFunctionId::DomSetText, 2)),
            (String::from("getText"), NativeFunction::new("getText", NativeFunctionId::DomGetText, 1)),
            (String::from("setStyle"), NativeFunction::new("setStyle", NativeFunctionId::DomSetStyle, 3)),
            (String::from("getStyle"), NativeFunction::new("getStyle", NativeFunctionId::DomGetStyle, 2)),
            (String::from("addClass"), NativeFunction::new("addClass", NativeFunctionId::DomAddClass, 2)),
            (String::from("removeClass"), NativeFunction::new("removeClass", NativeFunctionId::DomRemoveClass, 2)),
        ]
    }

    /// 要素情報を取得（デバッグ用）
    pub fn get_element_info(&self, id: usize) -> Option<ElementDebugInfo> {
        self.element_cache.get(&id).map(|elem| ElementDebugInfo {
            id: elem.id,
            tag_name: elem.tag_name.clone(),
            html_id: elem.html_id.clone(),
            classes: elem.classes.clone(),
            text_content: elem.text_content.clone(),
            child_count: elem.children.len(),
        })
    }

    /// DOM状態をダンプ（デバッグ用）
    pub fn dump_state(&self) -> String {
        let mut output = String::from("DOM State:\n");
        for (id, elem) in &self.element_cache {
            output.push_str(&format!(
                "  #{}: <{}> id={:?} classes={:?} children={}\n",
                id, elem.tag_name, elem.html_id, elem.classes, elem.children.len()
            ));
        }
        output
    }
}

impl Default for DomBinding {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Document Node (HTMLパーサーからの入力用)
// ============================================================================

/// HTMLパーサーからのドキュメントノード
#[derive(Debug, Clone)]
pub struct DocumentNode {
    /// タグ名
    pub tag_name: String,
    /// id属性
    pub id: Option<String>,
    /// クラス名リスト
    pub classes: Vec<String>,
    /// 属性
    pub attributes: BTreeMap<String, String>,
    /// テキストコンテンツ
    pub text_content: String,
    /// 子ノード
    pub children: Vec<DocumentNode>,
}

impl DocumentNode {
    pub fn new(tag_name: &str) -> Self {
        Self {
            tag_name: String::from(tag_name),
            id: None,
            classes: Vec::new(),
            attributes: BTreeMap::new(),
            text_content: String::new(),
            children: Vec::new(),
        }
    }

    pub fn with_id(mut self, id: &str) -> Self {
        self.id = Some(String::from(id));
        self
    }

    pub fn with_class(mut self, class: &str) -> Self {
        self.classes.push(String::from(class));
        self
    }

    pub fn with_text(mut self, text: &str) -> Self {
        self.text_content = String::from(text);
        self
    }

    pub fn with_child(mut self, child: DocumentNode) -> Self {
        self.children.push(child);
        self
    }

    pub fn with_attribute(mut self, name: &str, value: &str) -> Self {
        self.attributes.insert(String::from(name), String::from(value));
        self
    }
}

// ============================================================================
// Debug Info
// ============================================================================

/// 要素デバッグ情報
#[derive(Debug, Clone)]
pub struct ElementDebugInfo {
    pub id: usize,
    pub tag_name: String,
    pub html_id: Option<String>,
    pub classes: Vec<String>,
    pub text_content: String,
    pub child_count: usize,
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dom_binding_basic() {
        let mut binding = DomBinding::new();

        // HTMLを初期化
        let root = DocumentNode::new("html")
            .with_child(DocumentNode::new("body")
                .with_child(DocumentNode::new("div")
                    .with_id("main")
                    .with_class("container")
                    .with_text("Hello World")));

        binding.initialize_from_html(&root);

        // getElementById
        let result = binding.handle_operation(DomOperation::GetElementById(String::from("main")));
        assert!(matches!(result, ScriptValue::Element(_)));

        // getElementsByClass
        let result = binding.handle_operation(DomOperation::GetElementsByClass(String::from("container")));
        if let ScriptValue::Array(elements) = result {
            assert_eq!(elements.len(), 1);
        } else {
            panic!("Expected array");
        }
    }

    #[test]
    fn test_create_element() {
        let mut binding = DomBinding::new();

        let result = binding.handle_operation(DomOperation::CreateElement(String::from("div")));
        assert!(matches!(result, ScriptValue::Element(_)));
    }

    #[test]
    fn test_set_text() {
        let mut binding = DomBinding::new();

        // 要素を作成
        let elem = binding.handle_operation(DomOperation::CreateElement(String::from("span")));
        if let ScriptValue::Element(ref e) = elem {
            // テキストを設定
            binding.handle_operation(DomOperation::SetText(e.id, String::from("Test Text")));

            // テキストを取得
            let text = binding.handle_operation(DomOperation::GetText(e.id));
            assert_eq!(text, ScriptValue::String(String::from("Test Text")));
        } else {
            panic!("Expected element");
        }
    }
}
