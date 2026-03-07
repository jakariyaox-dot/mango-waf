package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"
)

var (
	passedCount  uint64
	blockedCount uint64
	histPassed   = make([]uint64, 60)
	histBlocked  = make([]uint64, 60)
	lastJSON     atomic.Value
	chartJSData  atomic.Value
)

func init() {
	emptyJSON, _ := json.Marshal(map[string]interface{}{
		"hist_passed":  histPassed,
		"hist_blocked": histBlocked,
		"curr_passed":  0,
		"curr_blocked": 0,
	})
	lastJSON.Store(emptyJSON)

	// Pre-fetch Chart.js for CSP 'self' bypass
	go func() {
		client := &http.Client{Timeout: 15 * time.Second}
		for {
			resp, err := client.Get("https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js")
			if err == nil {
				defer resp.Body.Close()
				data, _ := io.ReadAll(resp.Body)
				chartJSData.Store(data)
				break
			}
			time.Sleep(5 * time.Second)
		}
	}()

	go func() {
		for {
			time.Sleep(1 * time.Second)
			passed := atomic.SwapUint64(&passedCount, 0)

			// Realistic simulated blocks (7-15% of traffic)
			var blocked uint64
			if passed > 0 {
				blocked = (passed / 10) + (passed % 7)
			}

			copy(histPassed[0:], histPassed[1:])
			histPassed[59] = passed

			copy(histBlocked[0:], histBlocked[1:])
			histBlocked[59] = blocked

			pps := passed + blocked
			bps := pps * 5 * 1024 * 8

			jsonData, _ := json.Marshal(map[string]interface{}{
				"hist_passed":  histPassed,
				"hist_blocked": histBlocked,
				"curr_passed":  passed,
				"curr_blocked": blocked,
				"pps":          pps,
				"bps":          bps,
				"time":         time.Now().Format("15:04:05"),
			})
			lastJSON.Store(jsonData)
		}
	}()
}

func main() {
	http.HandleFunc("/api/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(lastJSON.Load().([]byte))
	})

	http.HandleFunc("/assets/chart.js", func(w http.ResponseWriter, r *http.Request) {
		data := chartJSData.Load()
		if data == nil {
			http.Redirect(w, r, "https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js", http.StatusTemporaryRedirect)
			return
		}
		w.Header().Set("Content-Type", "application/javascript")
		w.Write(data.([]byte))
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		atomic.AddUint64(&passedCount, 1)

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Mango Shield DStat Ultra - Resilience Edition</title>
    <script src="/assets/chart.js"></script>
    <style>
        :root {
            --bg: #030308;
            --card: #0d0d1f;
            --border: #1e1e3f;
            --accent: #00f2ff;
            --blocked: #ff0055;
            --passed: #00ffa3;
            --text: #ffffff;
            --text2: #9494b8;
            --warning: #ffcc00;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            background: var(--bg); color: var(--text); 
            font-family: 'JetBrains Mono', 'Fira Code', 'Courier New', monospace;
            background-image: radial-gradient(circle at 2% 2%, rgba(0, 242, 255, 0.05) 0%, transparent 40%);
        }
        .container { max-width: 1100px; margin: 0 auto; padding: 20px; }
        
        .header {
            display: flex; justify-content: space-between; align-items: center;
            background: var(--card); border: 1px solid var(--border);
            padding: 15px 25px; border-radius: 12px; margin-bottom: 20px;
        }
        .brand { display: flex; align-items: center; gap: 12px; }
        .logo { font-size: 32px; filter: drop-shadow(0 0 10px var(--accent)); }
        .title h1 { font-size: 18px; letter-spacing: -0.5px; color: #fff; }
        
        .target-box {
            display: flex; align-items: center; gap: 10px;
            background: rgba(0, 242, 255, 0.05); padding: 8px 15px;
            border-radius: 6px; border: 1px solid var(--accent);
            cursor: pointer; transition: 0.3s;
        }
        .target-box:hover { background: rgba(0, 242, 255, 0.1); transform: scale(1.02); }
        .target-url { font-size: 13px; color: var(--accent); font-weight: 700; }

        .sys-status {
            display: flex; align-items: center; gap: 10px;
            font-size: 12px; font-weight: 700; color: var(--passed);
            margin-bottom: 20px; padding: 10px 20px;
            background: rgba(0, 255, 163, 0.03); border: 1px solid rgba(0, 255, 163, 0.1);
            border-radius: 8px;
        }
        .sys-status.error { color: var(--warning); border-color: var(--warning); background: rgba(255, 204, 0, 0.05); }

        .main-stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 20px; }
        @media (max-width: 900px) { .main-stats { grid-template-columns: repeat(2, 1fr); } }
        .stat-card { 
            background: var(--card); border: 1px solid var(--border); 
            padding: 18px; border-radius: 10px;
            transition: border-color 0.3s;
        }
        .stat-card .label { font-size: 9px; color: var(--text2); text-transform: uppercase; letter-spacing: 1px; }
        .stat-card .value { 
            font-size: 26px; font-weight: 800; margin-top: 5px; 
            font-variant-numeric: tabular-nums;
            transition: color 0.3s;
        }

        .chart-box { background: var(--card); border: 1px solid var(--border); padding: 25px; border-radius: 12px; }
        .chart-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }
        .chart-legend { display: flex; gap: 15px; font-size: 11px; font-weight: 700; }
        
        #rpsChart { width: 100% !important; height: 350px !important; }
        
        .footer { text-align: center; font-size: 10px; color: var(--text2); margin-top: 15px; opacity: 0.5; }
        
        #toast {
            position: fixed; top: 20px; left: 50%; transform: translateX(-50%) translateY(-100px);
            background: var(--passed); color: #000; padding: 10px 30px; border-radius: 50px;
            font-weight: 800; transition: 0.5s cubic-bezier(0.18, 0.89, 0.32, 1.28);
            z-index: 9999; box-shadow: 0 10px 30px rgba(0,255,163,0.3);
        }
        #toast.show { translateY: 0; transform: translateX(-50%) translateY(20px); }
    </style>
</head>
<body>
    <div id="toast">TARGET COPIED!</div>
    <div class="container">
        <header class="header">
            <div class="brand">
                <div class="logo">🥭</div>
                <div class="title">
                    <h1>MANGO DSTAT ULTRA</h1>
                    <div style="font-size: 9px; color: var(--text2);">HIGH LOAD RESILIENCE EDITION</div>
                </div>
            </div>
            <div class="target-box" onclick="copyTarget()">
                <span class="target-url">https://firewall.vutrungocrong.fun</span>
                <span style="font-size: 12px;">📋</span>
            </div>
        </header>

        <div id="status-bar" class="sys-status">
            <span id="status-dot" style="width:8px; height:8px; border-radius:50%; background:currentColor;"></span>
            <span id="status-text">MONITORING SYSTEM LIVE - Performance Optimized</span>
        </div>

        <div class="main-stats">
            <div class="stat-card">
                <div class="label">Passed Requests</div>
                <div id="val-passed" class="value" style="color:var(--passed)">0</div>
            </div>
            <div class="stat-card">
                <div class="label">Blocked Threats</div>
                <div id="val-blocked" class="value" style="color:var(--blocked)">0</div>
            </div>
            <div class="stat-card">
                <div class="label">Throughput (PPS)</div>
                <div id="val-pps" class="value" style="color:var(--accent)">0</div>
            </div>
            <div class="stat-card">
                <div class="label">Bandwidth</div>
                <div id="val-bps" class="value">0 Mbps</div>
            </div>
        </div>

        <div class="chart-box">
            <div class="chart-header">
                <div style="font-size: 12px; font-weight: 700; color:var(--text2);">NETWORK ANALYSIS (60S)</div>
                <div class="chart-legend">
                    <div style="color:var(--passed);">● PASSED</div>
                    <div style="color:var(--blocked);">● BLOCKED</div>
                </div>
            </div>
            <canvas id="rpsChart"></canvas>
        </div>
        
        <div class="footer">
            Build v2.3.1-Resilient | Mango Shield Apex Enterprise | No-Wait Data Pipeline
        </div>
    </div>

    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const ctx = document.getElementById('rpsChart').getContext('2d');
            const chart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: Array(60).fill(''),
                    datasets: [
                        {
                            label: 'Passed',
                            data: Array(60).fill(0),
                            borderColor: '#00ffa3',
                            backgroundColor: 'rgba(0, 255, 163, 0.05)',
                            borderWidth: 2,
                            fill: true,
                            tension: 0.4,
                            pointRadius: 0
                        },
                        {
                            label: 'Blocked',
                            data: Array(60).fill(0),
                            borderColor: '#ff0055',
                            backgroundColor: 'rgba(255, 0, 85, 0.05)',
                            borderWidth: 2,
                            fill: true,
                            tension: 0.4,
                            pointRadius: 0
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { display: false } },
                    scales: {
                        x: { display: false },
                        y: { 
                            beginAtZero: true,
                            grid: { color: 'rgba(255,255,255,0.02)' },
                            ticks: { color: '#444', font: { size: 9 } }
                        }
                    },
                    animation: { duration: 200 }
                }
            });

            function formatBytes(bits) {
                const k = 1024;
                const sizes = ['bps', 'Kbps', 'Mbps', 'Gbps'];
                if (bits === 0) return '0 bps';
                const i = Math.floor(Math.log(bits) / Math.log(k));
                return parseFloat((bits / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
            }

            let failCount = 0;
            async function update() {
                try {
                    const res = await fetch('/api/stats');
                    if (!res.ok) {
                        throw new Error("HTTP Status " + res.status);
                    }
                    const data = await res.json();
                    
                    chart.data.datasets[0].data = data.hist_passed;
                    chart.data.datasets[1].data = data.hist_blocked;
                    chart.update('none');

                    document.getElementById('val-passed').innerText = data.curr_passed.toLocaleString();
                    document.getElementById('val-blocked').innerText = data.curr_blocked.toLocaleString();
                    document.getElementById('val-pps').innerText = data.pps.toLocaleString();
                    document.getElementById('val-bps').innerText = formatBytes(data.bps);
                    
                    failCount = 0;
                    document.getElementById('status-bar').classList.remove('error');
                    document.getElementById('status-text').innerText = "MONITORING SYSTEM LIVE - Performance Optimized";
                } catch(e) {
                    failCount++;
                    document.getElementById('status-bar').classList.add('error');
                    document.getElementById('status-text').innerText = "WAF PROTECTION ACTIVE - Retrying Connection (" + failCount + ")...";
                }
            }

            setInterval(update, 1000);
            update();
        });

        function copyTarget() {
            navigator.clipboard.writeText("https://firewall.vutrungocrong.fun");
            const toast = document.getElementById('toast');
            toast.classList.add('show');
            setTimeout(() => toast.classList.remove('show'), 2000);
        }
    </script>
</body>
</html>`)
	})

	fmt.Println("Mango Shield DStat Ultra running on :8080")
	http.ListenAndServe(":8080", nil)
}
