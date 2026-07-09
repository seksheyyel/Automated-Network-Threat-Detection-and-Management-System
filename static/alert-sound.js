const AudioCtx = window.AudioContext || window.webkitAudioContext;
const audioCtx = new AudioCtx();
document.addEventListener('click', () => {
    if (audioCtx.state === 'suspended') audioCtx.resume();
}, { once: true });

function playAlertSound() {
    const beep = (freq, start, dur) => {
        const osc = audioCtx.createOscillator();
        const gain = audioCtx.createGain();
        osc.connect(gain);
        gain.connect(audioCtx.destination);
        osc.type = 'square';
        osc.frequency.value = freq;
        gain.gain.setValueAtTime(0.5, audioCtx.currentTime + start);
        gain.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + start + dur);
        osc.start(audioCtx.currentTime + start);
        osc.stop(audioCtx.currentTime + start + dur);
    };
    beep(880, 0, 0.18);
    beep(1046, 0.2, 0.18);
}

async function checkForNewAlerts() {
    try {
        const res = await fetch('/api/alerts');
        const data = await res.json();
        if (!data.alerts || !data.alerts.length) return;
        const latest = data.alerts[0].timestamp;
        const lastSeen = localStorage.getItem('threatmon_last_alert_ts');
        if (lastSeen === null) {
            localStorage.setItem('threatmon_last_alert_ts', latest);
            return;
        }
        if (latest > lastSeen) {
            playAlertSound();
            localStorage.setItem('threatmon_last_alert_ts', latest);
        }
    } catch (e) {
        console.error(e);
    }
}

checkForNewAlerts();
setInterval(checkForNewAlerts, 5000);