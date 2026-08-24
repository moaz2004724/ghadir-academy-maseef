import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './ghadir_academy.jsx'

class GlobalErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null, errorInfo: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error("Critical Runtime Error caught by ErrorBoundary:", error, errorInfo);
    this.setState({ errorInfo });
  }

  handleReset = () => {
    localStorage.clear();
    sessionStorage.clear();
    window.location.href = '/';
  };

  render() {
    if (this.state.hasError) {
      return (
        <div style={{
          minHeight: "100vh",
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          background: "#070A13",
          color: "#fff",
          fontFamily: "'Cairo', sans-serif",
          direction: "rtl",
          padding: "20px",
          textAlign: "center"
        }}>
          <div style={{
            background: "#0F172A",
            border: "1px solid rgba(239, 68, 68, 0.3)",
            borderRadius: "16px",
            padding: "32px",
            maxWidth: "500px",
            boxShadow: "0 10px 40px rgba(0,0,0,0.5)"
          }}>
            <div style={{ fontSize: "40px", marginBottom: "16px" }}>⚠️</div>
            <h2 style={{ fontSize: "20px", fontWeight: "800", marginBottom: "12px", color: "#F87171" }}>
              حدث خطأ أثناء تحميل الصفحة
            </h2>
            <p style={{ fontSize: "13px", color: "#94A3B8", marginBottom: "20px", lineHeight: "1.6" }}>
              يرجى إعادة تحميل الصفحة أو إعادة تعيين الذاكرة المؤقتة للمتصفح.
            </p>
            {this.state.error && (
              <div style={{
                background: "rgba(0,0,0,0.4)",
                padding: "10px 14px",
                borderRadius: "8px",
                fontSize: "11px",
                color: "#FCA5A5",
                marginBottom: "20px",
                direction: "ltr",
                textAlign: "left",
                overflowX: "auto",
                fontFamily: "monospace"
              }}>
                {String(this.state.error.message || this.state.error)}
              </div>
            )}
            <div style={{ display: "flex", gap: "10px", justifyContent: "center" }}>
              <button
                onClick={() => window.location.reload()}
                style={{
                  background: "#2563EB",
                  color: "#fff",
                  border: "none",
                  padding: "10px 20px",
                  borderRadius: "8px",
                  fontWeight: "700",
                  cursor: "pointer",
                  fontFamily: "'Cairo', sans-serif"
                }}
              >
                إعادة المحاولة 🔄
              </button>
              <button
                onClick={this.handleReset}
                style={{
                  background: "rgba(239,68,68,0.2)",
                  color: "#EF4444",
                  border: "1px solid rgba(239,68,68,0.3)",
                  padding: "10px 20px",
                  borderRadius: "8px",
                  fontWeight: "700",
                  cursor: "pointer",
                  fontFamily: "'Cairo', sans-serif"
                }}
              >
                مسح الذاكرة المؤقتة 🧹
              </button>
            </div>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

ReactDOM.createRoot(document.getElementById('root')).render(
  <GlobalErrorBoundary>
    <App />
  </GlobalErrorBoundary>
)

